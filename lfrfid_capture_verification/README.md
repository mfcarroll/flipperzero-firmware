# `furi_hal_rfid` exact-period fix — verification tooling and records

Companion branch for the `furi_hal_rfid` exact-period patch. **Nothing here is proposed for merge, and
none of it is part of the build** — it is the harnesses and the raw records behind the PR's verification
section, published so the claims can be checked rather than taken on trust.

Two independent questions were asked, so there are two harnesses.

## 1. Did the reported durations change by exactly one interrupt latency? — `measure_capture_latency.py`

Standalone; needs only `pyserial` and a Flipper on USB. It drives the two *existing* CLI commands
(`rfid raw_read ask <file>`, `rfid raw_analyze <file>`) and reduces what the HAL reported.

```
python3 measure_capture_latency.py <label> <captures> <out.json>     # once per firmware build
python3 measure_capture_latency.py --compare base1.json,base2.json patched.json
```

⚠ **Run the baseline twice, bracketing the patched build.** Between two measurements of *identical*
firmware 25 minutes apart the reported HIGH width drifted 0.5 µs and the derived LOW 0.6 µs — larger than
the residual that drift was masquerading as. The period comes from the tag's own clock and is stable;
HIGH depends on envelope shape and threshold, which is analogue. Pooling two baselines that bracket the
patched run cancels it. The script's docstring records the other two traps (cluster, don't average; the
standard error is not the error bar) and why each produced a wrong answer first.

`capture_latency_runs/` holds the raw duration pairs from both runs, so `--compare` reproduces the PR's
table without any hardware:

```
python3 measure_capture_latency.py --compare \
    capture_latency_runs/run1_A_base.json,capture_latency_runs/run1_C_base.json \
    capture_latency_runs/run1_B_patched.json
```

Run 1 is the 40-capture run quoted in the PR. Run 2 is an independent replication on a later build —
note its LOW control lands at **−0.041 µs**, the opposite sign to run 1's +0.087. A real effect cannot
change sign, which is what retires that residual as noise.

## 2. Did any protocol decoder change its answer? — `lf_suite.py`

Per protocol per build: a Proxmark writes the tag, **the Proxmark verifies it in place immediately before
the Flipper reads it**, then the Flipper reads up to ten times at a recorded air gap. The two tools are
independent implementations, so neither is trusted and their *agreement* is the evidence; a Proxmark
verify failure is a bench fault, not a firmware finding, and it short-circuits the row.

- `lf_suite_compare.py` — diffs two artefacts. Pass = **identical verdicts**, not "still works". A
  protocol failing the same way on both sides is pre-existing, not caused by the change.
- `audit_artefacts.py` — an independent auditor that imports nothing from the suite. It re-derives, from
  the raw text alone, whether each row's identity is traceable to the value that was *asked for*, and
  prints the rows whose identity is weaker by construction instead of hiding them.
- `artefacts/` — the records: clone command, Proxmark verification, per-attempt decode, air gap, firmware
  commit and full raw CLI text, for every protocol on every build.

⚠ **Air gap is a first-class variable.** 6 mm for most protocols, 3 mm for `keri` / `indala224` /
`indala26`, 9 mm for `em4100_16`; the last two windows are disjoint, so there is no universal height. Five
apparent firmware effects in this work turned out to be geometry, which is why the comparison refuses to
compare records taken at different gaps.

## Provenance and what was changed

- `lf_suite.py`, `lf_suite_compare.py`, `audit_artefacts.py` and `measure_capture_latency.py` are
  **byte-identical to the files that produced these records.**
- `t5577_campaign.py` is a **mechanically extracted subset** of a larger research harness — only the six
  helpers `lf_suite.py` imports, plus their transitive dependencies, verbatim. The rest of that module is
  unrelated to this verification. Extracting it, rather than editing the import out of `lf_suite.py`, is
  what keeps the suite byte-identical.
- The artefacts are **redacted in two places**: a local username in Proxmark session-log paths, and the
  page-1 factory-traceability words of an unrelated personal credential that some spare tags carry from an
  earlier restore. Both are incidental Proxmark output. No decode, verdict, air gap or firmware commit is
  affected, and that is established directly: **all 32 redacted rows sit inside a `Page 1` section, none
  inside `Page 0`, and neither redacted word appears among the 20 block words any row asked for.**
  ⚠ An earlier draft of this note argued it from `audit_artefacts.py` reaching its findings unchanged on
  the redacted files. That argument was empty — the block check it rested on could not fail (it
  substring-tested asked-for words against output containing the echoed `write` commands). The check is
  fixed here, page-aware and index-bound; the conclusion above stands on the direct evidence instead.
