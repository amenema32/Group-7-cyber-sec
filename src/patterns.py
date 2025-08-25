import re

# Auth failures
AUTH_PATTERNS = [
    re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[0-9.]+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>[0-9.]+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9.]+)"),
    re.compile(r"sudo: .*authentication failure;.*rhost=(?P<ip>[0-9.]+)"),
]

# Suspicious command usage
CMD_PATTERNS = [
    re.compile(r"\b(nc|netcat)\b"),
    re.compile(r"\b(wget|curl)\b.*http"),
    re.compile(r"\bpython -c\b"),
    re.compile(r"\b/bin/bash -i\b"),
]
