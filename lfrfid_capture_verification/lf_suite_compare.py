#!/usr/bin/env python3
"""Compare two lf_suite runs. The pass criterion is IDENTICAL VERDICTS, not "still works".

    python3 lf_suite_compare.py baseline.json fixed.json

⚠ WHAT COUNTS AS A REGRESSION, and the distinctions are the whole point:
  CHANGED      the two builds disagree about the protocol or the identity  -> THE finding
  LOST_READ    read on the baseline, no longer reads on the other build    -> a finding
  GAINED_READ  did not read on the baseline, reads now                     -> report, do not celebrate
  SAME         identical verdict                                           -> pass
  INCONSISTENT the same tag decoded MORE THAN ONE WAY on either build        -> THE finding
  UNSCORED     NO_READ or INCONCLUSIVE on either side                      -> NOT a result; re-run it
  CLONE_MISMATCH the two arms programmed the tag DIFFERENTLY                 -> not comparable at all
               (for T55XX: rows the clone string holds the literal block words, so this
                also catches two arms that wrote different bits to the tag)
A protocol that fails IDENTICALLY on both builds is pre-existing, and it is excluded rather than counted
against the change under test.
"""
import json, sys
from collections import OrderedDict


def load(path, by_label=False):
    """Keyed by (protocol, silicon) normally. --by-label collapses silicon so two runs on DIFFERENT
    carriers can be compared -- which asks a different and useful question: does the verdict depend on
    the silicon? Keeping it opt-in matters, because silently collapsing the key would let a
    silicon-specific difference hide inside a build comparison."""
    d = OrderedDict()
    for r in json.load(open(path)):
        d[(r["label"], "*" if by_label else r.get("silicon", "?"))] = r
    return d


def verdict(r):
    # ⚠ A ROW MAY HAVE SEVERAL CORRECT ANSWERS, and then "whichever came first" is not the verdict.
    # em4100_multi is a T5577 holding TWO EM4100 frames: a read syncs on whichever it finds first, so
    # one arm can legitimately land on 1122334455 and the other on AABBCCDDEE. Comparing first-hits
    # would report that as CHANGED -- a fabricated regression out of pure sampling.
    # ⚠ Nor is the observed SET the verdict: with ten reads, seeing both is likely but not guaranteed,
    # so {A} vs {A,B} is also sampling. What is meaningful is whether every decode fell inside the
    # DECLARED set. A value outside it still shows as a difference, because that is a real misdecode.
    want = r.get("want") or {}
    if "any_of" in want:
        ok = {v.upper() for v in want["any_of"]}
        seen = {(d or "").split(" ", 1)[-1].upper() for d in (r.get("distinct") or [])}
        return ("any_of:all-declared",) if seen and seen <= ok else ("any_of:UNDECLARED", tuple(sorted(seen)))
    return (r.get("got_name"), r.get("got_data"))


def main():
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    by_label = "--by-label" in sys.argv
    if len(args) != 2:
        sys.exit(__doc__)
    a, b = load(args[0], by_label), load(args[1], by_label)
    def tag(d, dflt):
        if not d:
            return dflt
        r = next(iter(d.values()))
        return f"{r['build']}/{r.get('silicon', '?')}"
    an, bn = tag(a, "A"), tag(b, "B")
    keys = list(OrderedDict.fromkeys(list(a) + list(b)))
    rows, counts = [], OrderedDict()
    for k in keys:
        ra, rb = a.get(k), b.get(k)
        # ⛔ NEVER COMPARE ACROSS AIR GAPS. Position determines WHETHER a protocol reads -- em4100_16 is
        # 0/5 at 7mm and 5/5 at 8mm, indala26 reads at 3-6mm and not at 9mm -- so comparing a 3mm baseline
        # against a 9mm run manufactures a LOST_READ out of pure geometry. That is exactly how this suite
        # produced its one false regression, and a guard is cheaper than remembering.
        if ra is not None and rb is not None:
            pa, pb = ra.get("position", "unrecorded"), rb.get("position", "unrecorded")
            if pa != pb:
                counts["POSITION_MISMATCH"] = counts.get("POSITION_MISMATCH", 0) + 1
                rows.append((k, "POSITION_MISMATCH", f"{pa} vs {pb} -- NOT COMPARABLE"))
                continue
        # ⛔ NEVER COMPARE ACROSS DIFFERENT CLONE COMMANDS -- the same reason as the air-gap guard
        # above. gproxii's baseline was captured with `--xor 0`, which writes an undemodulable
        # biphase frame and scored INCONCLUSIVE, while the fixed arm used the working `--xor 141`.
        # That shows up as a GAINED_READ, i.e. as though the FIX had rescued the protocol, when the
        # only thing that changed was our own Proxmark argument. A tag programmed differently is a
        # different experiment, and a comparison that hides that manufactures a firmware finding.
        if ra is not None and rb is not None:
            ca, cb = ra.get("pm3_clone", ""), rb.get("pm3_clone", "")
            if ca and cb and ca != cb:
                counts["CLONE_MISMATCH"] = counts.get("CLONE_MISMATCH", 0) + 1
                rows.append((k, "CLONE_MISMATCH", "different clone command -- NOT COMPARABLE"))
                continue
        if ra is None or rb is None:
            cls = "MISSING"
            note = f"only in {an if rb is None else bn}"
        # ⛔⛔ ORDER MATTERS AND I HAD IT WRONG. This used to test "NO_READ on either side -> UNSCORED"
        # FIRST, which swallowed the single most important case: READ on the baseline and NO_READ on the
        # other build is a LOST_READ -- a regression -- not an absence of data. It mislabelled a real
        # em4100_16 regression on Invengo silicon as UNSCORED, i.e. as nothing to see. A classifier whose
        # catch-all sits above its findings reports "incomplete" instead of "broken".
        # UNSCORED now means only what it should: neither side produced a usable read, or a bench fault.
        # ⛔⛔ INCONSISTENT IS A FINDING, AND IT WAS NOT HANDLED AT ALL. The suite detects it -- the
        # same tag decoding two DIFFERENT ways across attempts -- but this comparison had no case for
        # it, with two bad outcomes: base READ against other INCONSISTENT fell into LOST_READ, which
        # understates a decoding disagreement as a missed read; and INCONSISTENT on BOTH sides fell
        # all the way through to `verdict(ra) != verdict(rb)` and, when the first hit happened to
        # match, was reported as SAME -- a tag decoding several ways called a clean pass. It must sit
        # ABOVE the catch-alls, for the same reason LOST_READ does.
        elif "INCONSISTENT" in (ra["status"], rb["status"]):
            cls, note = "INCONSISTENT", f"{ra['status']} / {rb['status']} -- decoded MORE THAN ONE WAY"
        elif ra["status"] == "READ" and rb["status"] != "READ":
            cls, note = "LOST_READ", f"{ra['status']} -> {rb['status']}"
        elif ra["status"] != "READ" and rb["status"] == "READ":
            cls, note = "GAINED_READ", f"{ra['status']} -> {rb['status']}"
        elif ra["status"] in ("NO_READ", "INCONCLUSIVE") or rb["status"] in ("NO_READ", "INCONCLUSIVE"):
            cls = "UNSCORED"
            note = f"{ra['status']} / {rb['status']}"
        elif verdict(ra) != verdict(rb):
            cls, note = "CHANGED", f"{verdict(ra)} -> {verdict(rb)}"
        else:
            cls = "SAME"
            note = f"{ra['got_name']} {ra['got_data']}"
            # ⚠ ASK WHETHER AN IDENTITY CHECK HAPPENED, not whether a hardcoded expectation existed.
            # Checking `want` mislabelled viking and pac_stanley as name-only when both had their
            # identity confirmed against the PM3's own decode -- understating the evidence, which in a
            # submission is its own kind of wrong.
            if not (ra.get("id_ok") is True and rb.get("id_ok") is True):
                why = []
                for tag, r in (("baseline", ra), ("other", rb)):
                    if r.get("id_ok") is None:
                        why.append(f"{tag}: no comparable identity field")
                    elif r.get("id_ok") is False:
                        why.append(f"{tag}: identity MISMATCH")
                note += "   (name-only -- " + "; ".join(why) + ")"
        counts[cls] = counts.get(cls, 0) + 1
        rows.append((k, cls, note))

    print(f"\n  {an}  vs  {bn}\n")
    print(f"  {'protocol':16s} {'silicon':12s} {'verdict':12s} detail")
    for (label, sil), cls, note in rows:
        print(f"  {label:16s} {sil:12s} {cls:12s} {note}")
    print("\n  " + "  ".join(f"{k}={v}" for k, v in counts.items()))

    # ⚠ LOST_READ AND GAINED_READ ARE CANDIDATES, NOT CONCLUSIONS. A protocol that reads intermittently
    # produces both from pure coupling noise: em4100_16 gave 3/3 and then 0/10 on the SAME build, SAME
    # tag, SAME command an hour apart, and the first comparison duly reported a LOST_READ regression that
    # did not exist. A read/no-read flip between two single-shot samples of a bimodal process carries no
    # information. Only CHANGED -- a different protocol or identity from a tag that read on both sides --
    # is a finding on its own evidence.
    candidates = counts.get("LOST_READ", 0) + counts.get("GAINED_READ", 0)
    regress = counts.get("CHANGED", 0) + counts.get("INCONSISTENT", 0)
    # ⚠ DERIVE THE UNSCORED COUNT, DO NOT HAND-MAINTAIN IT. This was a sum of named keys, and adding
    # a guard without extending the sum made the total silently too LOW -- it reported 4 protocols
    # incomplete when 5 were, i.e. it understated its own ignorance, which is the one direction that
    # matters. Anything that is not a pass or a finding is by definition unscored, so ask that instead
    # of listing the classes: a guard added later is counted whether or not anyone remembers to.
    SCORED = ("SAME", "CHANGED", "LOST_READ", "GAINED_READ", "INCONSISTENT")
    unscored = sum(v for k, v in counts.items() if k not in SCORED)
    print()
    if regress:
        print(f"  *** {regress} REGRESSION(S). A decoder returned a DIFFERENT answer on a tag that read")
        print("  *** on both builds. On this patch that means the decoder was relying on the capture")
        print("  *** bias -- an UPSTREAM FINDING to report, not a result to bury.")
    # ⚠ PASS IS FOR CLEAN RUNS ONLY. This printed "1 REGRESSION(S)" and then "PASS: 5 protocol(s)"
    # in the same summary, because the PASS branch only guarded against candidates and unscored rows.
    # A reader skimming for the last line would have taken a regression for a pass.
    if regress:
        pass
    elif candidates:
        print(f"  ⚠ {candidates} read/no-read FLIP(S) -- CANDIDATES REQUIRING ISOLATION, not findings.")
        print("  ⚠ A protocol that reads intermittently produces these from coupling alone. Before")
        print("  ⚠ believing one: re-run BOTH builds at ONE untouched placement with --attempts 10. If")
        print("  ⚠ the baseline cannot reproduce its own success, there is nothing to explain.")
    elif unscored:
        print(f"  INCOMPLETE: {unscored} protocol(s) never produced a comparable pair. No verdict is")
        print("  available for those, and claiming a clean pass while they are unscored would be the")
        print("  same error as reporting a total from a comparison that did not happen.")
    else:
        print(f"  PASS: {counts.get('SAME', 0)} protocol(s), identical verdicts on both builds.")
        nameonly = sum(1 for _, c, n in rows if c == "SAME" and "name-only" in n)
        if nameonly:
            print(f"  ⚠ {nameonly} of those are NAME-ONLY (identity not pinned) -- weaker evidence.")
    sys.exit(1 if regress else 0)   # a candidate flip is not a failure exit


if __name__ == "__main__":
    main()
