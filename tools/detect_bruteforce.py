#!/usr/bin/env python3
"""
detect_bruteforce.py - Naive brute-force detector over parsed EVTX events.

DESIGN NOTE (intentional): this is a deliberately HIGH-RECALL first pass.
It counts ALL failed-logon events per source IP and flags any source over
the threshold. It does NOT try to distinguish real password failures from
system/service noise -- that judgment is delegated to the verification
layer (verify_finding.py). This mirrors real triage: cast a wide net first,
then prune false positives in a separate, inspectable stage.

Usage:
    python3 detect_bruteforce.py <parsed.jsonl> [findings.json] [threshold]
"""
import sys, json
from collections import defaultdict

# Failed-logon event IDs we treat as brute-force candidates.
FAILED_LOGON_IDS = {"18456", "4625", "4771"}

def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events

def detect(events, threshold):
    # Group failed-logon events by source IP.
    by_ip = defaultdict(list)
    for ev in events:
        if ev.get("event_id") in FAILED_LOGON_IDS and ev.get("source_ip"):
            by_ip[ev["source_ip"]].append(ev)

    findings = []
    for ip, evs in by_ip.items():
        if len(evs) >= threshold:
            findings.append({
                "type": "brute_force_suspected",
                "source_ip": ip,
                "failed_attempts": len(evs),        # NAIVE count (all failures)
                "threshold": threshold,
                "computer": evs[0].get("computer"),
                "accounts_targeted": sorted({e.get("account") for e in evs if e.get("account")}),
                "first_seen": min(e.get("timestamp", "") for e in evs),
                "last_seen": max(e.get("timestamp", "") for e in evs),
                # Traceability: exact records that produced this finding.
                "evidence_record_ids": [e.get("record_id") for e in evs],
                "source_file": evs[0].get("source_file"),
                "verified": False,                  # verifier will set this
            })
    return findings

def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: detect_bruteforce.py <parsed.jsonl> [findings.json] [threshold]")
    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "findings.json"
    threshold = int(sys.argv[3]) if len(sys.argv) > 3 else 5

    events = load_events(in_path)
    findings = detect(events, threshold)

    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Scanned {len(events)} events. Flagged {len(findings)} suspected brute-force source(s) "
          f"(threshold={threshold}).")
    for fnd in findings:
        print(f"  [!] {fnd['source_ip']} -> {fnd['failed_attempts']} failed logons "
              f"on {fnd['computer']} (records {fnd['evidence_record_ids'][0]}..{fnd['evidence_record_ids'][-1]})")

if __name__ == "__main__":
    main()
