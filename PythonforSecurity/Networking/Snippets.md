# Build an interactive, prompt-based CLI

Resource from [ACI Learning](https://www.acilearning.com/)

## Objectives:

At the end of this episode, I will be able to:

1. Create a prompt-based Python command-line interface.

-----------------------------------------------------------

### Snippets

* What are Snippets?
  - Snippets are essentially small, self-contained pieces of code, text, or configuration that can be easily inserted and reused in different contexts. 

* Why use Snippets?
  - They promote code reuse, reduce redundancy, and streamline development or configuration processes. 

* How Snippet Networks Work:
  - Centralized Management: A network administrator can create and manage snippets in a central location, and then these snippets can be shared and deployed to multiple sites or devices on the network. 
  - Sharing and Collaboration: Snippets can be shared among users or teams, facilitating collaboration and knowledge sharing. 
  - Automation: Snippets can automate tasks or configurations, making it easier to deploy changes or set up new environments. 

### Snippet Lectures

* [Computer Networking Lab Snippet #1](https://www.youtube.com/watch?v=GejEZA_B14I&ab_channel=NatashaBondsTechPortfolio)
* [Computer Networking Lab Snippet #2](https://www.youtube.com/watch?v=zymD0aWYeGo&ab_channel=NatashaBondsTechPortfolio)

### Snippets Example

**complete cli.py**

```python
    #!/usr/bin/env python
from PyInquirer import prompt
from subprocess import call
from platform import system

questions = [
    dict(
        type="input",
        name="ip",
        message="What is the IP of the machine your are trying to ping?",
    ),
    dict(type="input", name="pings", message="How many times do you want to ping?"),
]


def ping(address, n=1):
    flag = "-n" if "windows" in system().lower() else "-c"
    command = ["ping", flag, n, address] 
    return call(command) == 0


def clear():
    command = "cls" if "windows" in system().lower() else "clear"
    call(command)


def main():
    clear()
    answers = prompt(questions)
    success = ping(answers["ip"], answers["pings"])
    if not success:
        print(f"Had some issues pinging {answers['ip']}")


if __name__ == "__main__":
    main()
```

-----------------------------------------------------------

### External Resources:

During this episode, you can reference the following external resources for supplementary tools and information:

- (S) [Python Poetry Tool](https://python-poetry.org/)
- (S) [PyInquirer Library](https://github.com/CITGuru/PyInquirer)
