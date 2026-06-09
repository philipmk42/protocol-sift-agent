#!/usr/bin/env python3
"""verify_finding.py - Independent verification layer for brute-force findings."""
import sys, json

REAL_FAILURE_MARKERS = [
    "password did not match",
    "login failed for user",
]
NOISE_MARKERS = [
    "attempting to use an nt account name",
]
NOISE_ACCOUNT_PREFIXES = ["##ms_"]

def load_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

def classify(event):
    blob = (event.get("raw_data") or "").lower()
    acct = (event.get("account") or "").lower()
    if any(acct.startswith(p) for p in NOISE_ACCOUNT_PREFIXES):
        return "noise"
    if any(m in blob for m in NOISE_MARKERS):
        return "noise"
    if any(m in blob for m in REAL_FAILURE_MARKERS):
        return "real"
    return "unknown"

def verify(findings, events, threshold):
    by_record = {e.get("record_id"): e for e in events}
    verified = []
    for fnd in findings:
        real_ids, noise_ids, unknown_ids = [], [], []
        for rid in fnd.get("evidence_record_ids", []):
            ev = by_record.get(rid)
            if ev is None:
                continue
            v = classify(ev)
            if v == "real":
                real_ids.append(rid)
            elif v == "noise":
                noise_ids.append(rid)
            else:
                unknown_ids.append(rid)
        real_count = len(real_ids)
        original = fnd.get("failed_attempts")
        still_brute = real_count >= threshold
        corrected = dict(fnd)
        corrected.update({
            "verified": True,
            "verdict": "confirmed_brute_force" if still_brute else "false_positive",
            "original_naive_count": original,
            "verified_real_failures": real_count,
            "noise_filtered_out": len(noise_ids),
            "real_failure_record_ids": real_ids,
            "noise_record_ids": noise_ids,
            "correction_note": (
                f"Naive detector counted {original} failed events. Verification "
                f"identified {real_count} genuine credential failure(s) and filtered "
                f"{len(noise_ids)} system/service-noise event(s). "
                + ("Finding CONFIRMED." if still_brute
                   else f"Finding RETRACTED as false positive (real failures {real_count} < threshold {threshold}).")
            ),
        })
        verified.append(corrected)
    return verified

def main():
    if len(sys.argv) < 3:
        sys.exit("Usage: verify_finding.py <findings.json> <parsed.jsonl> [out.json]")
    findings = json.load(open(sys.argv[1]))
    events = load_jsonl(sys.argv[2])
    out_path = sys.argv[3] if len(sys.argv) > 3 else "verified_findings.json"
    threshold = findings[0]["threshold"] if findings else 5
    verified = verify(findings, events, threshold)
    json.dump(verified, open(out_path, "w"), indent=2)
    print(f"Verified {len(verified)} finding(s) -> {out_path}\n")
    for v in verified:
        flag = "OK " if v["verdict"] == "confirmed_brute_force" else ">> "
        print(f"{flag}{v['source_ip']}: naive={v['original_naive_count']} "
              f"real={v['verified_real_failures']} noise={v['noise_filtered_out']} "
              f"=> {v['verdict'].upper()}")
        print(f"    {v['correction_note']}\n")

if __name__ == "__main__":
    main()
