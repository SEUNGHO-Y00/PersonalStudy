## 1.6 Modules and Packages

### 1.6.1 Importing a Module

### 1.6.2 Module Execution Context

### 1.6.3 Module Search Path

### 1.6.4 Packages and Sub-packages

### 1.6.5 The __init__.py File

### 1.6.6 Reloading Modules (Development Convenience)

### 1.6.7 Virtual Environments

### 1.6.8 Installing External Packages

### 1.6.9 Distributing Your Own Package

### 1.6.10 __all__ and import *

### 1.6.11 Resource Files Inside Packages

### 1.6.12 Best-Practice Checklist

### 1.6.13 Exercises

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
