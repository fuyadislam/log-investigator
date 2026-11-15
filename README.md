# Log Investigator

A small SOC-style tool in Python. It reads a firewall log and an authentication log, skips the broken lines, works out what is actually going on (brute force, logins after lots of failures, scans, watchlisted IPs) and writes a ranked investigation report.

COMP H2702 Scripting for Cybersecurity, individual project, Scenario A: Security Log Investigation.
HKM Fuyad Islam, TU Dublin.

## Example output

The top of the findings list and the risk table from a run on the supplied dataset:

```text
[ RANKED FINDINGS ]
  #1  [HIGH] Login success after repeated failures - 203.0.113.77 (evidence: 17)
       17 failed logins then a success as admin on vpn01 at 2026-10-12 14:51:00. Could be a guessed password, or just a user who mistyped. This IP is also on the suspicious list.
  #2  [HIGH] Successful login from watchlisted IP - 198.51.100.18 (evidence: 1)
       svc_backup logged in to files01 with ssh_key at 2026-10-12 08:12:20. The IP is on the suspicious list, so check if this login was expected.
  #3  [HIGH] Brute-force login attempts - 198.51.100.23 (evidence: 46)
       Up to 16 failures inside 30 min, 46 in total, against admin, administrator, root, svc_backup. Active from 2026-10-12 09:00:00 to 2026-10-12 10:30:00.

[ TOP RISK IPs ]
  IP               level   score  blocked  failed  locks  notes
  203.0.113.55     HIGH      138       78      20      0  watchlist
  198.51.100.23    HIGH      138        1      46      5  watchlist
  203.0.113.77     HIGH      122       23      17      0  watchlist
```

On this dataset the tool reads 892 valid firewall events and 514 valid authentication events, skips 12 malformed lines (7 and 5) and reports 21 findings: 4 HIGH, 11 MEDIUM and 6 LOW. The full report is in [`sample_output/investigation_report.txt`](sample_output/investigation_report.txt).

All the data in `data/` is the synthetic teaching dataset from the module. The public-looking IPs are documentation ranges, so they are only data values. The script never contacts them.

## Requirements

- Python 3.8 or newer
- No extra packages. Everything comes from the standard library (`ipaddress`, `datetime`, `collections`, `csv`, `json`, `argparse`).

`requirements.txt` has no packages in it on purpose, so `pip install -r requirements.txt` works without doing anything.

## Setup

```bash
git clone https://github.com/fuyadislam/log-investigator.git
cd log-investigator
```

That's it, no install step.

## How to run

From the project folder:

```bash
python log_investigator.py
```

This uses the files in `data/` and saves the reports in `output/`.

On macOS and Linux use `python3` instead of `python` (e.g. `python3 log_investigator.py`). On Windows it's `python` or `py`.

Options:

| Option | Default | What it does |
| --- | --- | --- |
| `--firewall` | `data/firewall.log` | firewall log to read |
| `--auth` | `data/authentication.log` | authentication log to read |
| `--watchlist` | `data/suspicious_ips.txt` | suspicious IP list (optional) |
| `--output` | `output` | folder for the reports |
| `--top` | `5` | how many items in the top lists |
| `--brute-force` | `10` | failed logins inside the window that count as brute force |
| `--window` | `30` | brute force window in minutes |

Example with a stricter brute force rule:

```bash
python log_investigator.py --brute-force 5 --window 10
```

`python log_investigator.py --help` shows the same list.

## Input files

| File | Format |
| --- | --- |
| `firewall.log` | `timestamp ACTION src=<ip> dst=<ip> proto=<TCP/UDP> port=<n> bytes=<n>` |
| `authentication.log` | `timestamp EVENT user=<name> src=<ip> host=<host> method=<method>` |
| `suspicious_ips.txt` | one IP per line, lines starting with `#` are ignored |

## Output

The report is printed to the console and saved as:

| File | What is in it |
| --- | --- |
| `output/investigation_report.txt` | the same report you see on screen |
| `output/investigation_report.json` | everything, for loading into other tools |
| `output/findings.csv` | the ranked findings |
| `output/ip_risk.csv` | every source IP with its risk score |

A copy of a full run is in `sample_output/` so you can see the result without running it.

## Project layout

```text
log_investigator.py   main script, arguments and error messages
parsers.py            reads the files, checks each line, skips bad ones
analysis.py           counts, detection rules, risk scoring, findings
report.py             builds the text report and saves txt/json/csv
tests/                unit tests
data/                 the supplied dataset
docs/                 workflow diagram and video script
sample_output/        reports from a full run
```

## How it works

![Workflow diagram: options are checked, the two logs and the watchlist are loaded and validated, the detection rules run, IPs are scored, and the report is printed and saved](docs/workflow.png)

## What it looks for

Basic counts for the firewall (allowed/blocked, unique IPs, top blocked IPs, top ports) and the auth log (success, failed, locked, top failed IPs and usernames).

On top of that, these rules turn into ranked findings. The names are the same ones the report uses:

| Finding | Rule | Severity |
| --- | --- | --- |
| Login success after repeated failures | 3+ failures then a success from the same IP within 60 min | HIGH |
| Successful login from watchlisted IP | any LOGIN_SUCCESS from an IP in `suspicious_ips.txt` | HIGH |
| Brute-force login attempts | 10+ failures from one IP inside 30 min | HIGH |
| IP active in both firewall and auth logs | outside IP with blocked traffic and failed logins, 10+ events total | MEDIUM |
| Account locked out | any ACCOUNT_LOCKED | MEDIUM |
| Many usernames tried from one IP | 3+ users and 10+ failures from one IP | MEDIUM |
| Blocked on many ports (possible scan) | one IP blocked on 10+ different ports | MEDIUM |
| Watchlisted IP allowed through firewall | ALLOWED firewall traffic from a watchlisted IP | MEDIUM |
| Blocked attempts on admin/database ports | outside IP blocked on 22, 23, 445, 3389, 3306 or 5432 | LOW |
| Watchlisted IP not seen in logs | in the list but not in either log | LOW |

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

```bash
python -m unittest discover tests
```

There are 6 tests. They check the parsers reject the same kinds of broken lines as the dataset, and that the brute force and success-after-failure rules fire when they should and stay quiet when they shouldn't.

## Limitations

- Thresholds are tuned to this dataset. Real logs would need them adjusted.
- A success after failures could just be someone who forgot their password. The tool flags it, a person still has to check.
- A watchlist hit is only as good as the list.
- It only reads these two log formats.

## AI use

The module allows AI tools with acknowledgement. I used Claude (Anthropic) to help with parts of the code and structure. I tested it, changed it and can explain every part.
