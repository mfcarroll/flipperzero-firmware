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

### Why this is differential, and not a comparison against the nominal

The obvious simpler design is to skip the second build entirely: the carrier divides `SystemCoreClock`
with no remainder at 125 kHz (`64e6/125e3 = 512`), so a carrier cycle is 8.000 µs and an RF/N half-bit is
`N*4` µs *exactly*. A field-clocked tag should therefore emit periods at exact multiples of that, and `L`
would just be the shortfall — one build, no differencing.

**It does not work, and the reason is worth recording.** Reducing the committed runs that way puts the
patched build — where `L` should read ~0 — at **2.44 µs**, and the per-cluster residuals there are
−0.641, +0.791 and +1.069 µs against nominals of 512, 768 and 1024 µs. That ~1 µs of scatter is analogue:
where the envelope crosses the comparator threshold depends on the shape of that particular edge, and a
period's high and low halves are composed differently at different run lengths. **It is comparable in
size to `L` itself (~1.8 µs), so it cannot be averaged away against a nominal — only cancelled.**
Differencing two builds cancels it exactly, which is what this harness does and why it needs both.

⚠ It is also a trap with a tidy-looking exit. Fitting `measured = k·q − L` across clusters at k = 2, 3, 4
returns a quantum of 256.86 µs against an exact 256.00 — a clean number, stable across all three runs,
and entirely an artefact: a lever arm of only Δk = 2 turns that 1.7 µs of scatter into 0.855 µs per k,
which is 0.334% on a 256 µs base, exactly the "scale error" it appears to show. The residuals refute it
in two lines — they are neither equal (so not an offset) nor proportional to k (residual/k *flips sign*
between k = 2 and k = 3, which a scale error cannot do). **A fitted parameter always returns a value; its
tidiness is not evidence the thing it names exists.**

⭐ **The differential arm also carries a control the absolute one cannot.** Because `L` is a constant per
captured interval, the base→patched shift must be the same at every interval length — and measured across
the three period clusters it is **+1.735 / +1.903 / +1.806 µs**. Constant across lengths *rules out* a
proportional error rather than assuming it away.

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
