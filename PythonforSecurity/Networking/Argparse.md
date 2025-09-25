# Build a Command Line Interface

Resource from [ACI Learning](https://www.acilearning.com/)

## Objectives:

At the end of this episode, I will be able to:

1. Discuss the features of a command-line interface.

2. Build a simple command-line interface using argparse.

-----------------------------------------------------------

### Argparse

Resource from [python.org](https://docs.python.org/3/library/argparse.html)

* The argparse module allows you to specify custom type converters for your command-line arguments.
* Click is multiple orders of magnitude better than argparse.
  - Click is generally considered more scalable due to its support for nested commands and its ability to handle more complex CLI structures with ease.

### Argparse Lectures

* [Argparse Basic Youtube](https://www.youtube.com/watch?v=FbEJN8FsJ9U&t=19s&ab_channel=JohnWatsonRooney)
* [Argparse Step by Step](https://www.datacamp.com/tutorial/python-argparse)

### Argparse Examples

**episode cli.py**

```python
    #!/usr/bin/env python

import argparse
import commands

def main():
    """Main entrypoint of the cli."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    # first command
    add = subparsers.add_parser(commands.ADD)
    add.add_argument("numbers", nargs="+", type=int)

    #second command
    sub = subparsers.add_parser(commands.SUBTRACT) 
    sub.add_argument('numbers', nargs='+', type=int)

    args = parser.parse_args()
    if args.command == commands.ADD:
        result = sum(args.numbers)
        print(f"The sum of {args.numbers} is {result}.")
    elif args.command == commands.SUBTRACT:
        first, *rest = args.numbers
        result = first - sum(rest)
        print(f"The difference of {args.numbers} is {result}.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

```

**episode commands.py**

```python
    ADD = 'add'
SUBTRACT = 'subtract'
```

**complete cli.py**

```python
    #!/usr/bin/env python
import commands
import argparse

def multiply(ns):
    """Multiplies all of the numbers contained in ns."""
    result = 1
    for n in ns:
        result *= n
    return result


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    add = subparsers.add_parser(commands.ADD)
    add.add_argument(
        "numbers",
        nargs="+",
        type=int,
    )

    sub = subparsers.add_parser(commands.SUBTRACT)
    sub.add_argument(
        "numbers",
        nargs="+",
        type=int,
    )

    mul = subparsers.add_parser(commands.MULTIPLY)
    mul.add_argument("numbers", nargs="+", type=int)

    div = subparsers.add_parser(commands.DIVIDE)
    div.add_argument("numbers", nargs="+", type=int)


    args = parser.parse_args()

    if args.command == commands.ADD:
        result = sum(args.numbers)
        operation = " + ".join(str(i) for i in args.numbers)
        print(f"The result of {operation} is {result}.")
    elif args.command == commands.SUBTRACT:
        first, *rest = args.numbers
        result = first - sum(rest)
        operation = " - ".join(str(i) for i in args.numbers)
        print(f"The result of {operation} is {result}.")
    elif args.command == commands.MULTIPLY:
        result = multiply(args.numbers)
        operation = " x ".join(str(i) for i in args.numbers)
        print(f"The result of {operation} is {result}.")
    elif args.command == commands.DIVIDE:
        first, *rest = args.numbers
        result = first / multiply(rest)
        operation = " ÷ ".join(str(i) for i in args.numbers)
        print(f"The result of {operation} is {result}.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

```

**complete commands.py**

```python
    ADD = "add"
SUBTRACT = "sub"
MULTIPLY = "mul"
DIVIDE = "div"

```

-----------------------------------------------------------

### External Resources:

During this episode, you can reference the following external resources for supplementary tools and information:

- (S) [Python argparse Module](https://docs.python.org/3/library/argparse.html)
