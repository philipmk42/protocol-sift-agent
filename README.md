# Protocol SIFT Agent — Self-Correcting DFIR Triage

An autonomous incident-response tooling pipeline that triages Windows Event Logs for brute-force activity and **catches its own false positives** before reporting them. Built for the SANS [FIND EVIL!](https://findevil.devpost.com) hackathon, designed to run on the SANS SIFT Workstation and be driven by Claude Code as the agentic execution engine.

## The core idea

Most detection scripts produce findings and trust them. The interesting failure mode in real incident response isn't *missing* an attack — it's **confidently reporting one that isn't there**. A handful of failed logins looks identical to a brute-force attempt until you actually inspect *why* each one failed.

This project addresses that by splitting detection into two deliberately separate layers:

1. **A naive detector** (`detect_bruteforce.py`) — intentionally high-recall. It counts *all* failed-logon events per source IP and flags anything over a threshold. It does not try to be clever.
2. **An independent verifier** (`verify_finding.py`) — re-examines the raw event records behind every finding, separates genuine credential failures from benign system/service noise, and **re-issues a corrected verdict** — retracting findings that don't hold up.

The intelligence lives in the *verification layer*, not buried inside the detector. This mirrors how a senior analyst actually works: cast a wide net first, then prune false positives in a separate, auditable pass. It also means self-correction is an **architectural property** of the system, not a prompt instruction the model might ignore.

## Self-correction in action

Run against `MSSQL_multiple_failed_logon_EventID_18456.evtx`, the pipeline does this:# protocol-sift-agent
Self-correcting autonomous DFIR agent for Windows Event Log triage — SANS FIND EVIL! hackathon
10.0.2.17: naive=10 real=2 noise=8 => FALSE_POSITIVE
Naive detector counted 10 failed events. Verification identified 2 genuine
credential failure(s) and filtered 8 system/service-noise event(s).
Finding RETRACTED as false positive (real failures 2 < threshold 5).

The naive detector sees 10 failed logons from one IP and flags brute force. The verifier re-reads all 10 records, recognizes that 8 are SQL Server internal certificate accounts (`##MS_...`, "Attempting to use an NT account name") rather than real password attempts, and **autonomously retracts the finding**. Every number traces back to specific event record IDs.

## Architecture

.evtx file
│
▼
parse_evtx.py        →  normalizes raw events to JSONL.
(uses SIFT's            Each record keeps source_file +
evtx_dump.py)          EventRecordID for full traceability.
│
▼
detect_bruteforce.py →  NAIVE, high-recall first pass.
Counts all failures per source IP.
│
▼
verify_finding.py    →  Independent re-examination.
Separates real failures from noise,
corrects or retracts the verdict.
│
▼
verified_findings.json  →  traceable, self-corrected output.

**Trust boundary:** evidence files are treated as read-only; the pipeline only ever reads `.evtx` input and writes to a separate `output/` directory. No tool modifies original evidence.

## Quick start

Requires a SANS SIFT Workstation (for the `evtx_dump.py` tool) and Python 3.

```bash
git clone https://github.com/philipmk42/protocol-sift-agent.git
cd protocol-sift-agent

# Get the sample evidence (Windows Event Log attack samples)
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git ~/evtx-samples

# 1. Parse a .evtx file into structured JSONL
python3 tools/parse_evtx.py \
  ~/evtx-samples/"Credential Access"/MSSQL_multiple_failed_logon_EventID_18456.evtx \
  output/mssql_parsed.jsonl

# 2. Run the naive detector (threshold = 5)
python3 tools/detect_bruteforce.py output/mssql_parsed.jsonl output/findings.json 5

# 3. Verify findings and self-correct
python3 tools/verify_finding.py output/findings.json output/mssql_parsed.jsonl output/verified_findings.json
```

## Project structure

protocol-sift-agent/
├── tools/
│   ├── parse_evtx.py         # .evtx → structured JSONL (traceable records)
│   ├── detect_bruteforce.py  # naive high-recall detector
│   └── verify_finding.py     # independent verifier + self-correction
├── output/                   # generated findings (sample run included)
├── LICENSE                   # MIT
└── README.md

## Dataset

Tested against [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), an open collection of real Windows Event Log samples mapped to MITRE ATT&CK techniques. Each file is a labeled mini-case with known ground truth, which makes accuracy self-assessment honest and reproducible.

## Limitations & honesty

- Currently covers one technique end-to-end (failed-logon / brute force, Event IDs 18456 / 4625 / 4771). The parser/detector/verifier pattern is designed to extend to other techniques, but only brute force is fully validated.
- The noise/real classification is rule-based (keyword and account-prefix matching tuned to observed samples). It is transparent and auditable, but would need broadened rules for production log diversity.
- IP and account extraction is regex-based against observed EventData formats; new log sources may require field-mapping adjustments.

These are documented deliberately — knowing where a detector is weak is part of trustworthy incident response.
## Note on execution logs and token usage

The execution log (`output/execution_log.jsonl`) records each tool invocation with a UTC timestamp, the exact command, return code, and full stdout/stderr — so any finding traces back to the specific tool run that produced it. Token-usage figures are intentionally absent: the detection and verification tools are **deterministic Python**, not LLM calls, so they consume no tokens. Placing the analytical logic in deterministic, auditable code (rather than in-model reasoning) is a deliberate trust decision — it makes every finding reproducible and independently verifiable, with no model nondeterminism in the evidence path.
## License

MIT — see [LICENSE](LICENSE).
