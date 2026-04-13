## 1.10 - Object-Oriented Programming (OOP)

### 1.10.1 Creating Classes

### 1.10.2 Attributes, Properties, and Encapsulation

### 1.10.3 Class Variables, Class Methods, Static Methods

### 1.10.4 Inheritance and the Method Resolution Order (MRO)

### 1.10.5 Abstract Base Classes (ABCs) and Protocols

### 1.10.6 Special (Dunder) Methods

### 1.10.7 Data Classes and attrs

### 1.10.8 Metaclasses (Advanced)

### 1.10.9 Performance Considerations

### 1.10.10 Design Principles

### 1.10.11 Exercises

1. Vector Class
    - Implement Vector2D with __add__, __sub__, __abs__, and __iter__. Support hashing when frozen.

```python
import math
from dataclasses import dataclass

@dataclass(frozen=True)
class Vector2D:
    x: float
    y: float

    def __add__(self, other: "Vector2D") -> "Vector2D":
        return Vector2D(self.x + other.x, self.y + other.y)

    def __sub__(self, other: "Vector2D") -> "Vector2D":
        return Vector2D(self.x - other.x, self.y - other.y)

    def __abs__(self) -> float:
        """Returns the magnitude (L2 norm) of the vector."""
        return math.hypot(self.x, self.y)

    def __iter__(self):
        """Allows unpacking: x, y = vector"""
        yield from (self.x, self.y)

# Quick Demo
v1 = Vector2D(3, 4)
v2 = Vector2D(1, 2)

print(f"Addition: {v1 + v2}")      # Vector2D(x=4, y=6)
print(f"Magnitude: {abs(v1)}")      # 5.0
print(f"Hashable: {hash(v1)}")      # Works because frozen=True
print(f"Unpacking: {list(v1)}")     # [3.0, 4.0]
```

2. Property Validation
    - Create Account(balance) where balance never drops below 0; deposit/withdraw methods must use the property.
  
```python
class Account:
    def __init__(self, initial_balance: float = 0.0) -> None:
        # Use the setter for validation during initialization
        self.balance = initial_balance

    @property
    def balance(self) -> float:
        return self._balance

    @balance.setter
    def balance(self, value: float) -> None:
        if value < 0:
            raise ValueError("Balance cannot drop below 0.")
        self._balance = value

    def deposit(self, amount: float) -> None:
        """Add funds using the property setter."""
        self.balance += amount

    def withdraw(self, amount: float) -> None:
        """Remove funds using the property setter."""
        self.balance -= amount

# Usage
acc = Account(100)
acc.withdraw(40)  # balance = 60
try:
    acc.withdraw(100)  # Raises ValueError
except ValueError as e:
    print(e)
```

3. ABC Plugin System
    - Design an abstract class Command with name and run(args); dynamically load subclasses from a plugins/ directory and execute them.

* Abstract
```python
from abc import ABC, abstractmethod
from typing import List

class Command(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """The identifier used to call the command."""
        pass

    @abstractmethod
    def run(self, args: List[str]) -> None:
        """The execution logic for the command."""
        pass
```

* Plug in
```python
import importlib
import pkgutil
import plugins  # Requires an empty __init__.py in the plugins/ folder

def discover_commands() -> dict[str, Command]:
    registry = {}
    
    # Iterate over modules in the plugins package
    for _, module_name, _ in pkgutil.iter_modules(plugins.__path__):
        full_module_name = f"plugins.{module_name}"
        module = importlib.import_module(full_module_name)
        
        # Find subclasses of Command within the module
        for attribute_name in dir(module):
            attribute = getattr(module, attribute_name)
            
            if (isinstance(attribute, type) and 
                issubclass(attribute, Command) and 
                attribute is not Command):
                
                cmd_instance = attribute()
                registry[cmd_instance.name] = cmd_instance
                
    return registry

# Example Execution
if __name__ == "__main__":
    commands = discover_commands()
    # If a plugin named 'hello' exists:
    if "hello" in commands:
        commands["hello"].run(["Alice"])
```

* Example
```python
class HelloCommand(Command):
    @property
    def name(self):
        return "hello"

    def run(self, args):
        print(f"Hello, {', '.join(args)}!")
```

4. Slots vs Dict Benchmark
    - Measure memory (sys.getsizeof) of 1 000 000 plain objects vs slotted objects holding two floats.

```python
import sys

class PointDict:
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y

class PointSlot:
    __slots__ = ('x', 'y')
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y

n = 1_000_000

# Measuring collection overhead + individual object overhead
dict_objs = [PointDict(1.1, 2.2) for _ in range(n)]
slot_objs = [PointSlot(1.1, 2.2) for _ in range(n)]

# Sample overhead for a single instance
d_size = sys.getsizeof(dict_objs[0]) + sys.getsizeof(dict_objs[0].__dict__)
s_size = sys.getsizeof(slot_objs[0])

print(f"Dict Object (approx): {d_size} bytes")
print(f"Slot Object (approx): {s_size} bytes")
print(f"Total List overhead: {sys.getsizeof(dict_objs) / 1024**2:.2f} MB")
```

5. Protocol Compliance
    - Write a function serialize(obj) that accepts anything meeting the protocol { to_json() -> str }. Show it working with a data class that defines to_json.

```python
import json
from typing import Protocol, runtime_checkable
from dataclasses import dataclass, asdict

@runtime_checkable
class JSONSerializable(Protocol):
    def to_json(self) -> str:
        """Method to convert the object to a JSON string."""
        ...

def serialize(obj: JSONSerializable) -> str:
    """Accepts any object that implements the to_json() method."""
    return obj.to_json()

@dataclass
class User:
    username: str
    email: str

    def to_json(self) -> str:
        return json.dumps(asdict(self))

# Usage
user = User(username="dev_pro", email="pro@example.com")
print(serialize(user))  # Works!
```
