# Accuracy Report

Self-assessment of the pipeline's findings accuracy, false positives, and known failure modes. Per the hackathon's guidance, honesty is valued over perfection — this documents what the system gets right *and* where it is weak.

## Test case

**Evidence:** `MSSQL_multiple_failed_logon_EventID_18456.evtx` (EVTX-ATTACK-SAMPLES, Credential Access)
**Events parsed:** 10
**Event type:** MSSQL Event ID 18456 (login failed)

## Result

| Stage | Output |
|-------|--------|
| Naive detector | Flagged `10.0.2.17` — **10 failed logons** → brute force suspected |
| Verifier | **2 genuine** credential failures, **8 system/service-noise** events filtered |
| Final verdict | **FALSE POSITIVE** — retracted (2 real failures < threshold of 5) |

## What the verifier caught

The naive detector counted all 10 failed-logon events from `10.0.2.17` as attack attempts. Independent verification found that 8 of those were SQL Server internal certificate accounts (`##MS_SQLResourceSigningCertificate##`, `##MS_PolicySigningCertificate##`, etc.) failing with the reason *"Attempting to use an NT account name with SQL Server Authentication"* — routine service noise, not credential guessing. Only 2 events (`sa`, `root` with *"Password did not match"*) were genuine failed credential attempts.

This is a **true negative correctly identified**: the source IP is not conducting a brute-force attack, and the system correctly retracts its initial finding rather than reporting a false alarm.

## False positives

- **Caught:** 8 false-positive failed-logon events, removed by the verification layer before final reporting.
- **Remaining risk:** the verifier relies on known noise markers. A noise pattern not yet in its rule set would pass through as a "real" failure and could inflate the genuine-failure count.

## Missed artifacts / known gaps

- **Single technique validated.** Only failed-logon brute force (Event IDs 18456 / 4625 / 4771) is fully tested. Other credential-access techniques in the dataset are not yet covered.
- **Rule-based classification.** Noise/real separation uses keyword and account-prefix matching tuned to observed samples — transparent and auditable, but not exhaustive across all Windows/application log formats.
- **Field extraction is format-specific.** Account and source-IP extraction is regex-based against the EventData layouts observed in test samples; a differently structured log source would need field-mapping adjustments.

## Hallucinated claims

None observed. Every reported number is derived directly from parsed event records, and each finding carries the specific `EventRecordID`s it was computed from, so any figure can be traced back to source events. The system does not generate narrative beyond what the record counts support.

## Evidence integrity

The pipeline treats evidence as read-only: tools only ever *read* the input `.evtx` file and *write* to a separate `output/` directory. No tool modifies original evidence. This is enforced by the tool design (input and output paths are distinct), not by a prompt instruction.
