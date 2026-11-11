# Video script (about 5 minutes)

Record with OBS, Teams or PowerPoint's screen recording. Voice only, no face needed.
Font size up in the terminal so it's readable. Don't show any passwords or tokens.

## 0:00 - 0:45  Scenario and problem
(show: README on GitHub)

"Hi, I'm Fuyad, student number D24128837. This is my COMP H2702 project, scenario A, security log investigation.
The problem is that firewall and login logs have hundreds of events and an analyst can't read them line by line.
They need to know who's attacking, whether anyone actually got in, and how much of the data they can trust.
So I built a Python tool that reads both logs and gives a ranked investigation report."

## 0:45 - 1:45  Inputs and workflow
(show: data/firewall.log, data/authentication.log, suspicious_ips.txt, then docs/workflow.png)

"These are the supplied logs. Each firewall line has a timestamp, ALLOWED or BLOCKED, source, destination, protocol, port and bytes.
The auth log has the event, user, source IP, host and method. Some lines are broken on purpose, like this one with no source IP,
and this one with port equals notaport.
This is the workflow. parsers.py reads and checks every line and skips the bad ones. analysis.py does the counts,
the detection rules and the risk score. report.py prints the report and saves it as TXT, JSON and CSV.
log_investigator.py ties it together with command-line options."

## 1:45 - 3:30  Run it
(run: python log_investigator.py, scroll slowly)

"First it tells me 7 firewall lines and 5 auth lines were skipped, and lists each one with the line number and reason,
so I know how much to trust the numbers.
Firewall summary: 892 valid events, 522 allowed, 370 blocked. Port 22, SSH, is blocked the most.
Auth summary: 163 failed logins and 5 account lockouts. The top targets are admin, svc_backup and root, all privileged accounts.
Then the ranked findings. Each one has a severity, the IP, how much evidence there is and a short explanation."

(optional: python log_investigator.py --brute-force 5 --window 10 to show thresholds can change)

## 3:30 - 4:30  What it means
(show: findings #1 to #3, then the risk table)

"Number one is the most important. 203.0.113.77 failed to log in as admin 17 times, then logged in successfully at 14:51.
That looks like a guessed password, and the IP is also on the watchlist. I'd check what that session did and reset the password.
Number three, 198.51.100.23, tried 46 times against four accounts and got admin locked five times. The lockout worked,
it never got in, but the attack kept coming back every day.
Number two is a service account logging in with an SSH key from a watchlisted IP. Could be normal, could be a stolen key,
so a person needs to check it.
At the bottom, every IP gets a risk score so the worst ones are at the top."

## 4:30 - 5:00  Error handling and a limitation
(run: python log_investigator.py --auth missing.log)

"If a file is missing it gives a clear error instead of crashing. Broken lines are skipped like we saw at the start.
One limitation is that the thresholds are tuned to this dataset. A slow attacker under ten failures in thirty minutes would be missed.
Next I'd add an IP reputation lookup and a timeline per IP. Thanks for watching."
