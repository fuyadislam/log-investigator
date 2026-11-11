# Log Investigator

COMP H2702 Scripting for Cybersecurity, individual project.
Scenario A: Security Log Investigation.
HKM Fuyad Islam, TU Dublin.

A small SOC-style tool in Python. It reads a firewall log and an authentication log, skips the broken lines, works out what is actually going on (brute force, logins after lots of failures, scans, watchlisted IPs) and writes a ranked investigation report.

All the data in `data/` is the synthetic teaching dataset from the module. The public-looking IPs are documentation ranges, so they are only data values. The script never contacts them.

## Requirements

- Python 3.8 or newer
- No extra packages. Everything comes from the standard library (`ipaddress`, `datetime`, `collections`, `csv`, `json`, `argparse`).

`requirements.txt` is there but empty on purpose, so `pip install -r requirements.txt` works without doing anything.

## Setup

```
git clone <this repo>
cd log-investigator
```

That's it, no install step.

## How to run

From the project folder:

```
python log_investigator.py
```

This uses the files in `data/` and saves the reports in `output/`.

Options:

| option | default | what it does |
|---|---|---|
| `--firewall` | `data/firewall.log` | firewall log to read |
| `--auth` | `data/authentication.log` | authentication log to read |
| `--watchlist` | `data/suspicious_ips.txt` | suspicious IP list (optional) |
| `--output` | `output` | folder for the reports |
| `--top` | `5` | how many items in the top lists |
| `--brute-force` | `10` | failed logins inside the window that count as brute force |
| `--window` | `30` | brute force window in minutes |

Example with a stricter brute force rule:

```
python log_investigator.py --brute-force 5 --window 10
```

`python log_investigator.py --help` shows the same list.

## Input files

| file | format |
|---|---|
| `firewall.log` | `timestamp ACTION src=<ip> dst=<ip> proto=<TCP/UDP> port=<n> bytes=<n>` |
| `authentication.log` | `timestamp EVENT user=<name> src=<ip> host=<host> method=<method>` |
| `suspicious_ips.txt` | one IP per line, lines starting with `#` are ignored |

## Output

The report is printed to the console and saved as:

- `output/investigation_report.txt` the same report you see on screen
- `output/investigation_report.json` everything, for loading into other tools
- `output/findings.csv` the ranked findings
- `output/ip_risk.csv` every source IP with its risk score

A copy of a full run is in `sample_output/` so you can see the result without running it.

## Project layout

```
log_investigator.py   main script, arguments and error messages
parsers.py            reads the files, checks each line, skips bad ones
analysis.py           counts, detection rules, risk scoring, findings
report.py             builds the text report and saves txt/json/csv
tests/                unit tests
data/                 the supplied dataset
docs/                 workflow diagram and video script
sample_output/        reports from a full run
```

## What it looks for

Basic counts for the firewall (allowed/blocked, unique IPs, top blocked IPs, top ports) and the auth log (success, failed, locked, top failed IPs and usernames).

On top of that, these rules turn into ranked findings:

| finding | rule | severity |
|---|---|---|
| Login success after repeated failures | 3+ failures then a success from the same IP within 60 min | HIGH |
| Successful login from watchlisted IP | any LOGIN_SUCCESS from an IP in suspicious_ips.txt | HIGH |
| Brute-force login attempts | 10+ failures from one IP inside 30 min | HIGH |
| IP active in both logs | outside IP with blocked traffic and failed logins, 10+ events total | MEDIUM |
| Account locked out | any ACCOUNT_LOCKED | MEDIUM |
| Many usernames tried from one IP | 3+ users and 10+ failures from one IP | MEDIUM |
| Possible port scan | one IP blocked on 10+ different ports | MEDIUM |
| Watchlisted IP allowed through | ALLOWED firewall traffic from a watchlisted IP | MEDIUM |
| Blocked on admin/database ports | outside IP blocked on 22, 23, 445, 3389, 3306 or 5432 | LOW |
| Watchlisted IP not seen | in the list but not in either log | LOW |

Every IP also gets a score (points for blocked traffic, failed logins, lockouts, watchlist, being in both logs, and successful logins that look suspicious). 60+ is HIGH, 25+ is MEDIUM. All the numbers are in `SETTINGS` at the top of `analysis.py` so they are easy to change.

I picked these numbers by looking at the dataset. With lower values, lots of normal internal machines with two or three typos started showing up as attacks, so I raised them until the findings were things an analyst would actually look at.

## Error handling

- Malformed lines (missing timestamp, empty `src=`, bad IP, `port=notaport`, unknown action/event) are skipped and listed with the line number and reason. The rest of the file still gets analysed.
- Missing log file, no permission, or a folder given instead of a file: clear error message and exit, no traceback.
- Log file with no valid lines at all: stops and says so, instead of making an empty report.
- Missing watchlist: warns and carries on, since it's optional. Invalid IPs in it are skipped.
- Bad option values (`--top 0`, negative window): rejected before anything runs.
- Can't write to the output folder: says so. The console report is already printed by then so nothing is lost.
- Odd bytes in a file are replaced instead of crashing the read.

## Tests

```
python -m unittest discover tests
```

Checks the parsers reject the same kinds of broken lines as the dataset, and that the brute force and success-after-failure rules fire when they should and stay quiet when they shouldn't.

## Limitations

- Thresholds are tuned to this dataset. Real logs would need them adjusted.
- A success after failures could just be someone who forgot their password. The tool flags it, a person still has to check.
- A watchlist hit is only as good as the list.
- It only reads these two log formats.

## AI use

The module allows AI tools with acknowledgement. I used Claude (Anthropic) to help with parts of the code and structure. I tested it, changed it and can explain every part.
