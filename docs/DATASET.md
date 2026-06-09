# Dataset Documentation

## Source

[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by SBousseaden — an open, community-maintained collection of real Windows Event Log (`.evtx`) samples, each capturing a specific attack or post-exploitation technique and mapped to the MITRE ATT&CK framework.

The samples are organized by ATT&CK tactic (Credential Access, Lateral Movement, Privilege Escalation, Defense Evasion, etc.). Each file is small (KB–MB) and represents a labeled mini-case with known ground truth, which makes accuracy self-assessment honest and the results fully reproducible.

## Why this dataset

The SANS FIND EVIL! starter evidence (multi-GB disk and memory images for the "Stark Research Labs" scenario) requires heavy mounting and memory-forensics tooling. EVTX-ATTACK-SAMPLES was chosen instead because it is:

- **Lightweight** — runs on modest hardware without mounting large images.
- **Structured** — Windows Event Logs are well-suited to the parse → detect → verify pipeline.
- **Reproducible** — anyone can clone the public repo and reproduce every result exactly.
- **Labeled** — each sample's technique is documented, giving ground truth for accuracy assessment.

## Specific file tested

| Field | Value |
|-------|-------|
| File | `MSSQL_multiple_failed_logon_EventID_18456.evtx` |
| Tactic | Credential Access |
| Event ID | 18456 (MSSQL "login failed") |
| Events | 10 |
| Source host | MSEDGEWIN10 |
| Source IP | 10.0.2.17 |

## What the agent found

Of 10 failed-logon events from `10.0.2.17`, the pipeline determined that 2 were genuine credential failures (`sa`, `root` — "Password did not match") and 8 were benign SQL Server internal certificate-account events ("Attempting to use an NT account name"). With a brute-force threshold of 5 genuine failures, the activity was correctly classified as **not a brute-force attack** — a false positive that the verification layer retracted.

## How to reproduce

```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git ~/evtx-samples
python3 tools/parse_evtx.py ~/evtx-samples/"Credential Access"/MSSQL_multiple_failed_logon_EventID_18456.evtx output/mssql_parsed.jsonl
python3 tools/detect_bruteforce.py output/mssql_parsed.jsonl output/findings.json 5
python3 tools/verify_finding.py output/findings.json output/mssql_parsed.jsonl output/verified_findings.json
```
