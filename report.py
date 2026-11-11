# report.py
# builds the text report and saves txt / json / csv files

import csv
import json
import os
from datetime import datetime

LINE = "=" * 70


def format_pairs(pairs, label):
    # turns [("1.2.3.4", 10), ...] into nice lines
    if not pairs:
        return ["    (none)"]
    return [f"    {str(key):<18} {count:>4} {label}" for key, count in pairs]


def build_text_report(results, problems, inputs):
    fw = results["firewall"]
    auth = results["auth"]
    lines = []

    lines.append(LINE)
    lines.append(" SECURITY LOG INVESTIGATION REPORT")
    lines.append(f" generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(LINE)
    lines.append(f" firewall log : {inputs['firewall']}")
    lines.append(f" auth log     : {inputs['auth']}")
    lines.append(f" watchlist    : {inputs['watchlist']} ({inputs['watchlist_size']} IPs)")

    # data quality first so the analyst knows how much to trust the numbers
    lines.append("")
    lines.append("[ DATA QUALITY ]")
    for name, bad in problems.items():
        lines.append(f"  {name}: {len(bad)} line(s) skipped")
        for b in bad:
            lines.append(f"    line {b['line']}: {b['reason']}")

    lines.append("")
    lines.append("[ FIREWALL SUMMARY ]")
    lines.append(f"  valid events      : {fw['valid_events']}")
    lines.append(f"  ALLOWED / BLOCKED : {fw['allowed']} / {fw['blocked']}")
    lines.append(f"  unique source IPs : {fw['unique_sources']} ({fw['external_sources']} external)")
    lines.append("  top blocked source IPs:")
    lines += format_pairs(fw["top_blocked_sources"], "blocked")
    lines.append("  most targeted ports (all traffic):")
    lines += format_pairs(fw["top_ports"], "events")
    lines.append("  most blocked ports:")
    lines += format_pairs(fw["top_blocked_ports"], "blocked")

    lines.append("")
    lines.append("[ AUTHENTICATION SUMMARY ]")
    lines.append(f"  valid events   : {auth['valid_events']}")
    lines.append(f"  LOGIN_SUCCESS  : {auth['success']}")
    lines.append(f"  LOGIN_FAILED   : {auth['failed']}")
    lines.append(f"  ACCOUNT_LOCKED : {auth['locked']}")
    lines.append(f"  LOGOUT         : {auth['logout']}")
    lines.append("  top failed-login source IPs:")
    lines += format_pairs(auth["top_failed_sources"], "failed")
    lines.append("  most targeted usernames:")
    lines += format_pairs(auth["top_targeted_users"], "failed")

    lines.append("")
    lines.append("[ RANKED FINDINGS ]")
    for f in results["findings"]:
        lines.append(f"  #{f['rank']:<2} [{f['severity']}] {f['title']} - {f['subject']} "
                     f"(evidence: {f['evidence_count']})")
        lines.append(f"       {f['explanation']}")

    lines.append("")
    lines.append("[ TOP RISK IPs ]")
    lines.append(f"  {'IP':<16} {'level':<7} {'score':>5} {'blocked':>8} {'failed':>7} {'locks':>6}  notes")
    for r in results["ip_risk"][:10]:
        notes = []
        if r["on_watchlist"]:
            notes.append("watchlist")
        if r["internal"]:
            notes.append("internal")
        lines.append(f"  {r['ip']:<16} {r['level']:<7} {r['score']:>5} {r['blocked']:>8} "
                     f"{r['failed_logins']:>7} {r['lockouts']:>6}  {', '.join(notes)}")

    lines.append(LINE)
    return "\n".join(lines)


def make_output_folder(folder):
    os.makedirs(folder, exist_ok=True)


def save_text(text, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text + "\n")


def save_json(results, problems, path):
    data = {"results": results, "skipped_lines": problems}
    # default=str turns the datetime objects into text, json can't save them otherwise
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def save_csv(rows, columns, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def save_all(results, problems, text, folder):
    # returns the list of files it wrote so main() can print them
    make_output_folder(folder)
    paths = {
        "txt": os.path.join(folder, "investigation_report.txt"),
        "json": os.path.join(folder, "investigation_report.json"),
        "findings_csv": os.path.join(folder, "findings.csv"),
        "ip_risk_csv": os.path.join(folder, "ip_risk.csv"),
    }
    save_text(text, paths["txt"])
    save_json(results, problems, paths["json"])
    save_csv(results["findings"],
             ["rank", "severity", "title", "subject", "evidence_count", "explanation"],
             paths["findings_csv"])
    save_csv(results["ip_risk"],
             ["ip", "level", "score", "blocked", "failed_logins", "lockouts", "on_watchlist", "internal"],
             paths["ip_risk_csv"])
    return list(paths.values())
