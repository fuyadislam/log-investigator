# log_investigator.py
# COMP H2702 project, scenario A: security log investigation
# HKM Fuyad Islam
# run it with:  python log_investigator.py
# or see options with:  python log_investigator.py --help

import argparse
import sys

from parsers import load_log, load_watchlist, parse_firewall_line, parse_auth_line
from analysis import SETTINGS, run_analysis
from report import build_text_report, save_all


def get_arguments():
    parser = argparse.ArgumentParser(
        description="Analyse firewall and authentication logs and produce an investigation report."
    )
    parser.add_argument("--firewall", default="data/firewall.log", help="path to firewall log")
    parser.add_argument("--auth", default="data/authentication.log", help="path to auth log")
    parser.add_argument("--watchlist", default="data/suspicious_ips.txt", help="suspicious ip list (optional)")
    parser.add_argument("--output", default="output", help="folder to save the reports in")
    parser.add_argument("--top", type=int, default=SETTINGS["top_n"], help="how many items in top lists")
    parser.add_argument("--brute-force", type=int, default=SETTINGS["brute_force_attempts"],
                        help="failed logins in the time window that count as brute force")
    parser.add_argument("--window", type=int, default=SETTINGS["brute_force_minutes"],
                        help="brute force time window in minutes")
    return parser.parse_args()


def check_settings(args):
    # don't let silly values through, e.g. --top 0 or a negative window
    if args.top < 1:
        raise ValueError("--top has to be 1 or more")
    if args.brute_force < 2:
        raise ValueError("--brute-force has to be at least 2")
    if args.window < 1:
        raise ValueError("--window has to be at least 1 minute")


def load_required_log(path, parse_function, name):
    # the two main logs are required, so if one can't be read I stop here
    # with a clear message instead of a python traceback
    try:
        events, bad = load_log(path, parse_function)
    except FileNotFoundError:
        print(f"[ERROR] {name} not found: {path}")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] no permission to read {name}: {path}")
        sys.exit(1)
    except IsADirectoryError:
        print(f"[ERROR] {name} path is a folder, not a file: {path}")
        sys.exit(1)

    if not events:
        print(f"[ERROR] {name} has no valid events in it ({len(bad)} bad lines). Nothing to analyse.")
        sys.exit(1)

    print(f"[+] {name}: {len(events)} valid events, {len(bad)} skipped")
    return events, bad


def main():
    args = get_arguments()

    try:
        check_settings(args)
    except ValueError as error:
        print(f"[ERROR] {error}")
        sys.exit(2)

    settings = dict(SETTINGS)
    settings["top_n"] = args.top
    settings["brute_force_attempts"] = args.brute_force
    settings["brute_force_minutes"] = args.window

    print("[*] loading logs...")
    fw_events, fw_bad = load_required_log(args.firewall, parse_firewall_line, "firewall log")
    auth_events, auth_bad = load_required_log(args.auth, parse_auth_line, "authentication log")

    watchlist, skipped_ips = load_watchlist(args.watchlist)
    if skipped_ips:
        print(f"[!] ignored {len(skipped_ips)} invalid entries in watchlist: {', '.join(skipped_ips)}")

    print("[*] analysing...")
    results = run_analysis(fw_events, auth_events, watchlist, settings)

    problems = {"firewall.log": fw_bad, "authentication.log": auth_bad}
    inputs = {
        "firewall": args.firewall,
        "auth": args.auth,
        "watchlist": args.watchlist,
        "watchlist_size": len(watchlist),
    }
    text = build_text_report(results, problems, inputs)
    print()
    print(text)

    # saving can fail too (read-only folder, file open in excel etc)
    # the console report is already printed so the work isn't lost
    try:
        saved = save_all(results, problems, text, args.output)
    except OSError as error:
        print(f"[ERROR] couldn't save the reports to '{args.output}': {error}")
        sys.exit(1)

    print("\n[+] reports saved:")
    for path in saved:
        print(f"    {path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] stopped by user")
        sys.exit(130)
