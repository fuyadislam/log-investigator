# parsers.py
# reads the log files and turns each line into a dictionary
# bad lines get skipped and saved with the reason so I can report them later

import ipaddress
from datetime import datetime

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

FIREWALL_ACTIONS = ["ALLOWED", "BLOCKED"]
FIREWALL_FIELDS = ["src", "dst", "proto", "port", "bytes"]

AUTH_EVENTS = ["LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT", "ACCOUNT_LOCKED"]
AUTH_FIELDS = ["user", "src", "host", "method"]


def read_lines(path):
    # errors="replace" so one weird byte doesn't kill the whole read
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def split_line(line, required_fields):
    # every line looks like: date time ACTION key=value key=value ...
    parts = line.split()
    if len(parts) < 3:
        raise ValueError("not enough fields")

    timestamp_text = parts[0] + " " + parts[1]
    try:
        timestamp = datetime.strptime(timestamp_text, TIME_FORMAT)
    except ValueError:
        raise ValueError("bad or missing timestamp")

    action = parts[2]

    fields = {}
    for part in parts[3:]:
        if "=" not in part:
            raise ValueError(f"field without '=': {part}")
        key, value = part.split("=", 1)
        fields[key] = value

    # check nothing is missing or left empty (e.g. "src=" with no ip)
    for name in required_fields:
        if name not in fields:
            raise ValueError(f"missing field '{name}'")
        if fields[name] == "":
            raise ValueError(f"empty field '{name}'")

    return timestamp, action, fields


def parse_firewall_line(line):
    timestamp, action, fields = split_line(line, FIREWALL_FIELDS)

    if action not in FIREWALL_ACTIONS:
        raise ValueError(f"unknown action '{action}'")
    if not is_valid_ip(fields["src"]):
        raise ValueError(f"bad source ip '{fields['src']}'")
    if not is_valid_ip(fields["dst"]):
        raise ValueError(f"bad destination ip '{fields['dst']}'")
    if not fields["port"].isdigit() or not 0 <= int(fields["port"]) <= 65535:
        raise ValueError(f"bad port '{fields['port']}'")
    if not fields["bytes"].isdigit():
        raise ValueError(f"bad byte count '{fields['bytes']}'")

    return {
        "time": timestamp,
        "action": action,
        "src": fields["src"],
        "dst": fields["dst"],
        "proto": fields["proto"].upper(),
        "port": int(fields["port"]),
        "bytes": int(fields["bytes"]),
    }


def parse_auth_line(line):
    timestamp, event, fields = split_line(line, AUTH_FIELDS)

    if event not in AUTH_EVENTS:
        raise ValueError(f"unknown event '{event}'")
    if not is_valid_ip(fields["src"]):
        raise ValueError(f"bad source ip '{fields['src']}'")

    return {
        "time": timestamp,
        "event": event,
        "user": fields["user"],
        "src": fields["src"],
        "host": fields["host"],
        "method": fields["method"],
    }


def load_log(path, parse_function):
    # goes through the file line by line
    # returns the good events and a list of the lines that failed
    events = []
    bad_lines = []

    lines = read_lines(path)
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if line == "":
            continue  # blank lines aren't really errors, just ignore them

        try:
            events.append(parse_function(line))
        except ValueError as error:
            bad_lines.append({"line": number, "reason": str(error), "text": line})

    return events, bad_lines


def load_watchlist(path):
    # suspicious_ips.txt, one ip per line, # lines are comments
    # this file is optional so if it's missing I just carry on without it
    watchlist = set()
    skipped = []

    try:
        lines = read_lines(path)
    except FileNotFoundError:
        print(f"[!] watchlist not found ({path}), carrying on without it")
        return watchlist, skipped

    for line in lines:
        ip = line.strip()
        if ip == "" or ip.startswith("#"):
            continue
        if is_valid_ip(ip):
            watchlist.add(ip)
        else:
            skipped.append(ip)

    return watchlist, skipped
