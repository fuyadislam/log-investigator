# analysis.py
# all the counting, detection rules and risk scoring
# nothing in here prints or writes files, that's report.py's job

from collections import Counter, defaultdict
from datetime import timedelta
import ipaddress

# thresholds I picked, explained in the README and the report
# main() can override some of them from the command line
SETTINGS = {
    "top_n": 5,
    "brute_force_attempts": 10,     # this many failed logins...
    "brute_force_minutes": 30,      # ...from one ip inside this many minutes
    "spray_min_users": 3,           # one ip failing against this many different users
    "spray_min_attempts": 10,       # ...with at least this many failures (stops normal typos showing up)
    "success_after_fail_min": 3,    # failed logins before a success from the same ip
    "success_after_fail_minutes": 60,
    "scan_min_ports": 10,           # one ip blocked on this many different ports
    "correlation_min_events": 10,   # blocked + failed needed before I flag an ip seen in both logs
    "sensitive_ports": [22, 23, 445, 3389, 3306, 5432],
    # points used for the per-ip risk score
    "weights": {
        "blocked": 1,
        "failed_login": 2,
        "lockout": 5,
        "watchlist": 10,
        "seen_in_both_logs": 10,
        "success_after_fail": 20,
        "watchlist_success": 25,
    },
    "high_score": 60,
    "medium_score": 25,
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# inside the same severity, this decides which kind of finding goes first
# a likely successful break-in matters more than attempts that failed
RULE_ORDER = [
    "Login success after repeated failures",
    "Successful login from watchlisted IP",
    "Brute-force login attempts",
    "IP active in both firewall and auth logs",
    "Account locked out",
    "Many usernames tried from one IP",
    "Blocked on many ports (possible scan)",
    "Watchlisted IP allowed through firewall",
    "Blocked attempts on admin/database ports",
    "Watchlisted IP not seen in logs",
]


def is_internal(ip):
    # private ranges (10.x, 192.168.x etc) count as our own network
    return ipaddress.ip_address(ip).is_private and not is_documentation_range(ip)


def is_documentation_range(ip):
    # the dataset uses these ranges for "outside" addresses
    # python treats them as private, so I have to check for them myself
    for net in ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
            return True
    return False


def analyse_firewall(events, top_n):
    actions = Counter(e["action"] for e in events)
    blocked = [e for e in events if e["action"] == "BLOCKED"]

    blocked_sources = Counter(e["src"] for e in blocked)
    all_ports = Counter(e["port"] for e in events)
    blocked_ports = Counter(e["port"] for e in blocked)

    return {
        "valid_events": len(events),
        "allowed": actions.get("ALLOWED", 0),
        "blocked": actions.get("BLOCKED", 0),
        "unique_sources": len(set(e["src"] for e in events)),
        "external_sources": len(set(e["src"] for e in events if not is_internal(e["src"]))),
        "top_blocked_sources": blocked_sources.most_common(top_n),
        "top_ports": all_ports.most_common(top_n),
        "top_blocked_ports": blocked_ports.most_common(top_n),
    }


def analyse_auth(events, top_n):
    event_counts = Counter(e["event"] for e in events)
    failed = [e for e in events if e["event"] == "LOGIN_FAILED"]
    locked = [e for e in events if e["event"] == "ACCOUNT_LOCKED"]

    return {
        "valid_events": len(events),
        "success": event_counts.get("LOGIN_SUCCESS", 0),
        "failed": event_counts.get("LOGIN_FAILED", 0),
        "logout": event_counts.get("LOGOUT", 0),
        "locked": event_counts.get("ACCOUNT_LOCKED", 0),
        "locked_accounts": Counter(e["user"] for e in locked).most_common(),
        "top_failed_sources": Counter(e["src"] for e in failed).most_common(top_n),
        "top_targeted_users": Counter(e["user"] for e in failed).most_common(top_n),
    }


def group_by_source(events):
    groups = defaultdict(list)
    for e in events:
        groups[e["src"]].append(e)
    for ip in groups:
        groups[ip].sort(key=lambda e: e["time"])
    return groups


def find_brute_force(auth_events, settings):
    # sliding window: for each failed login, count how many more
    # failures from the same ip land inside the next X minutes
    failed = [e for e in auth_events if e["event"] == "LOGIN_FAILED"]
    window = timedelta(minutes=settings["brute_force_minutes"])
    results = []

    for ip, attempts in group_by_source(failed).items():
        best = 0
        start = 0
        for end in range(len(attempts)):
            while attempts[end]["time"] - attempts[start]["time"] > window:
                start += 1
            best = max(best, end - start + 1)

        if best >= settings["brute_force_attempts"]:
            results.append({
                "ip": ip,
                "peak_attempts": best,
                "total_failed": len(attempts),
                "users": sorted(set(a["user"] for a in attempts)),
                "first_seen": attempts[0]["time"],
                "last_seen": attempts[-1]["time"],
            })
    return results


def find_password_spraying(auth_events, settings):
    # one ip trying lots of different usernames
    failed = [e for e in auth_events if e["event"] == "LOGIN_FAILED"]
    results = []
    for ip, attempts in group_by_source(failed).items():
        users = sorted(set(a["user"] for a in attempts))
        if len(users) >= settings["spray_min_users"] and len(attempts) >= settings["spray_min_attempts"]:
            results.append({"ip": ip, "users": users, "attempts": len(attempts)})
    return results


def find_success_after_failures(auth_events, settings):
    # a success straight after a run of failures from the same ip
    # could mean the attacker finally guessed the password
    window = timedelta(minutes=settings["success_after_fail_minutes"])
    results = []

    for ip, events in group_by_source(auth_events).items():
        recent_fails = []
        for e in events:
            if e["event"] == "LOGIN_FAILED":
                recent_fails.append(e)
            elif e["event"] == "LOGIN_SUCCESS":
                recent_fails = [f for f in recent_fails if e["time"] - f["time"] <= window]
                if len(recent_fails) >= settings["success_after_fail_min"]:
                    results.append({
                        "ip": ip,
                        "user": e["user"],
                        "host": e["host"],
                        "time": e["time"],
                        "fails_before": len(recent_fails),
                    })
                recent_fails = []
    return results


def find_port_scans(fw_events, settings):
    # one ip getting blocked on lots of different ports looks like a scan
    blocked = [e for e in fw_events if e["action"] == "BLOCKED"]
    results = []
    for ip, events in group_by_source(blocked).items():
        ports = sorted(set(e["port"] for e in events))
        if len(ports) >= settings["scan_min_ports"]:
            results.append({"ip": ip, "ports": ports, "attempts": len(events)})
    return results


def find_sensitive_port_hits(fw_events, settings, top_n):
    # blocked traffic from outside to remote admin / database ports (ssh, rdp, smb...)
    # internal ips are left out, they hit these ports all the time for normal reasons
    hits = Counter()
    ports_by_ip = defaultdict(set)
    for e in fw_events:
        if is_internal(e["src"]):
            continue
        if e["action"] == "BLOCKED" and e["port"] in settings["sensitive_ports"]:
            hits[e["src"]] += 1
            ports_by_ip[e["src"]].add(e["port"])
    return [{"ip": ip, "attempts": n, "ports": sorted(ports_by_ip[ip])}
            for ip, n in hits.most_common(top_n)]


def check_watchlist(fw_events, auth_events, watchlist):
    # what did each suspicious ip actually do in our logs?
    results = []
    for ip in sorted(watchlist):
        fw = [e for e in fw_events if e["src"] == ip]
        auth = [e for e in auth_events if e["src"] == ip]
        results.append({
            "ip": ip,
            "fw_allowed": sum(1 for e in fw if e["action"] == "ALLOWED"),
            "fw_blocked": sum(1 for e in fw if e["action"] == "BLOCKED"),
            "auth_failed": sum(1 for e in auth if e["event"] == "LOGIN_FAILED"),
            "auth_success": [e for e in auth if e["event"] == "LOGIN_SUCCESS"],
        })
    return results


def score_ips(fw_events, auth_events, watchlist, detections, settings):
    # adds up points for each ip so the worst ones float to the top
    w = settings["weights"]
    profiles = defaultdict(lambda: Counter())

    for e in fw_events:
        if e["action"] == "BLOCKED":
            profiles[e["src"]]["blocked"] += 1
    for e in auth_events:
        if e["event"] == "LOGIN_FAILED":
            profiles[e["src"]]["failed_login"] += 1
        elif e["event"] == "ACCOUNT_LOCKED":
            profiles[e["src"]]["lockout"] += 1
        elif e["event"] == "LOGIN_SUCCESS" and e["src"] in watchlist:
            profiles[e["src"]]["watchlist_success"] += 1

    for item in detections["success_after_failures"]:
        profiles[item["ip"]]["success_after_fail"] += 1

    scored = []
    for ip, counts in profiles.items():
        score = sum(counts[name] * w[name] for name in counts)
        if ip in watchlist:
            score += w["watchlist"]
        if counts["blocked"] and counts["failed_login"]:
            score += w["seen_in_both_logs"]

        if score >= settings["high_score"]:
            level = "HIGH"
        elif score >= settings["medium_score"]:
            level = "MEDIUM"
        else:
            level = "LOW"

        scored.append({
            "ip": ip,
            "score": score,
            "level": level,
            "internal": is_internal(ip),
            "on_watchlist": ip in watchlist,
            "blocked": counts["blocked"],
            "failed_logins": counts["failed_login"],
            "lockouts": counts["lockout"],
        })

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def build_findings(detections, watch_results, settings):
    # turns the raw detections into short findings an analyst can read
    findings = []

    def add(severity, title, subject, evidence, explanation):
        findings.append({
            "severity": severity,
            "title": title,
            "subject": subject,
            "evidence_count": evidence,
            "explanation": explanation,
        })

    # logins already caught by the success-after-failures rule, so I don't list them twice
    already_flagged = set((s["ip"], s["time"]) for s in detections["success_after_failures"])

    for w in watch_results:
        for s in w["auth_success"]:
            if (w["ip"], s["time"]) in already_flagged:
                continue
            add("HIGH", "Successful login from watchlisted IP", w["ip"], 1,
                f"{s['user']} logged in to {s['host']} with {s['method']} at {s['time']}. "
                "The IP is on the suspicious list, so check if this login was expected.")

    for s in detections["success_after_failures"]:
        add("HIGH", "Login success after repeated failures", s["ip"], s["fails_before"],
            f"{s['fails_before']} failed logins then a success as {s['user']} on {s['host']} "
            f"at {s['time']}. Could be a guessed password, or just a user who mistyped."
            + (" This IP is also on the suspicious list." if s["ip"] in detections["watchlist"] else ""))

    for b in detections["brute_force"]:
        add("HIGH", "Brute-force login attempts", b["ip"], b["total_failed"],
            f"Up to {b['peak_attempts']} failures inside {settings['brute_force_minutes']} min, "
            f"{b['total_failed']} in total, against {', '.join(b['users'])}. "
            f"Active from {b['first_seen']} to {b['last_seen']}.")

    for user, count in detections["lockouts"]:
        add("MEDIUM", "Account locked out", user, count,
            f"'{user}' was locked {count} time(s). Lockouts show the guessing was stopped, "
            "but repeated ones mean the attack kept coming back.")

    for c in detections["correlated"]:
        add("MEDIUM", "IP active in both firewall and auth logs", c["ip"], c["blocked"] + c["failed"],
            f"{c['blocked']} blocked connection(s) and {c['failed']} failed login(s). "
            "Same source hitting the network and the login service is a stronger sign than either alone.")

    for s in detections["spraying"]:
        add("MEDIUM", "Many usernames tried from one IP", s["ip"], s["attempts"],
            f"{len(s['users'])} different users tried ({', '.join(s['users'])}). "
            "Guessing across accounts looks like spraying or a username list.")

    for p in detections["port_scans"]:
        add("MEDIUM", "Blocked on many ports (possible scan)", p["ip"], p["attempts"],
            f"Blocked on {len(p['ports'])} ports: {', '.join(str(x) for x in p['ports'])}.")

    for h in detections["sensitive_ports"]:
        add("LOW", "Blocked attempts on admin/database ports", h["ip"], h["attempts"],
            f"Ports {', '.join(str(x) for x in h['ports'])}. The firewall stopped these, "
            "worth keeping an eye on but no sign they got through.")

    for w in watch_results:
        if w["fw_allowed"] > 0:
            add("MEDIUM", "Watchlisted IP allowed through firewall", w["ip"], w["fw_allowed"],
                f"{w['fw_allowed']} connection(s) from this IP were ALLOWED. Check what they reached.")
        total = w["fw_allowed"] + w["fw_blocked"] + w["auth_failed"] + len(w["auth_success"])
        if total == 0:
            add("LOW", "Watchlisted IP not seen in logs", w["ip"], 0,
                "No activity in these logs. Doesn't mean it's safe, it may just not have shown up yet.")

    # highest severity first, then the most evidence
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]],
                                 RULE_ORDER.index(f["title"]),
                                 -f["evidence_count"]))
    for rank, f in enumerate(findings, start=1):
        f["rank"] = rank
    return findings


def run_analysis(fw_events, auth_events, watchlist, settings):
    # main entry point for this file, main() just calls this
    top_n = settings["top_n"]

    fw_summary = analyse_firewall(fw_events, top_n)
    auth_summary = analyse_auth(auth_events, top_n)

    blocked_by_ip = Counter(e["src"] for e in fw_events if e["action"] == "BLOCKED")
    failed_by_ip = Counter(e["src"] for e in auth_events if e["event"] == "LOGIN_FAILED")
    # ips that show up in both logs, outside addresses only
    # lots of internal machines have a couple of each, that's just normal noise
    correlated = []
    for ip in blocked_by_ip:
        if ip not in failed_by_ip or is_internal(ip):
            continue
        if blocked_by_ip[ip] + failed_by_ip[ip] >= settings["correlation_min_events"]:
            correlated.append({"ip": ip, "blocked": blocked_by_ip[ip], "failed": failed_by_ip[ip]})
    correlated.sort(key=lambda c: c["blocked"] + c["failed"], reverse=True)

    detections = {
        "brute_force": find_brute_force(auth_events, settings),
        "spraying": find_password_spraying(auth_events, settings),
        "success_after_failures": find_success_after_failures(auth_events, settings),
        "port_scans": find_port_scans(fw_events, settings),
        "sensitive_ports": find_sensitive_port_hits(fw_events, settings, top_n),
        "lockouts": auth_summary["locked_accounts"],
        "correlated": correlated,
        "watchlist": watchlist,
    }

    watch_results = check_watchlist(fw_events, auth_events, watchlist)
    ip_scores = score_ips(fw_events, auth_events, watchlist, detections, settings)
    findings = build_findings(detections, watch_results, settings)

    return {
        "firewall": fw_summary,
        "auth": auth_summary,
        "findings": findings,
        "ip_risk": ip_scores,
        "watchlist": watch_results,
    }
