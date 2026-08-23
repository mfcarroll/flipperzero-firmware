"""INDEPENDENT audit of two artefacts. Deliberately imports NOTHING from lf_suite: code that
reuses the scoring under test cannot discover that the scoring is wrong.

    python3 audit_artefacts.py base.json fixed.json

Re-derives from the STORED RAW TEXT: that each recorded verdict appears verbatim in the capture,
that no attempt decoded differently from another, that both arms agree, and that every identity
claim can be traced back to what we ASKED the Proxmark to write.

⚠ TWO BLIND SPOTS FOUND BY RUNNING IT, both fixed here, both of which had it crying wolf:
 1. It scanned EVERY result-shaped line in an attempt. indala224 renders its 28-byte raw across
    four lines as bare hex pairs ("C2E31EBA 3CBEE4AF"), which look exactly like "name + data" --
    so it reported three distinct decodes where there was one. rfid_read takes the FIRST match
    and breaks, so the suite was never affected; the auditor was. It now mirrors that.
 2. It only looked for the asked value LITERALLY, so it flagged three rows that are fine for
    three different legitimate reasons: a decoded-equivalent pin (hid_h10301, independently
    confirmed by Wiegand arithmetic), a payload slice (nexwatch), and two independent
    implementations agreeing on FC/Card (securakey).
An auditor that cannot distinguish those from a real defect will get ignored, which is worse
than not having one."""
import json, re, sys

def load(p):
    d = json.load(open(p))
    return {r["label"]: r for r in (d["records"] if isinstance(d, dict) and "records" in d else d)}

if len(sys.argv) != 3:
    sys.exit(__doc__)
base, fixed = load(sys.argv[1]), load(sys.argv[2])
problems, notes = [], []

def attempts_of(raw):
    return (raw or "").split("---attempt---")

for arm, recs in (("base", base), ("fixed", fixed)):
    for lbl, r in recs.items():
        raw = r.get("raw") or ""
        name, data = r.get("got_name"), r.get("got_data")
        # 1. the recorded verdict must literally appear in the captured text
        if r["status"] == "READ":
            if not name or not data:
                problems.append(f"{arm}/{lbl}: status READ but name/data missing")
            elif not re.search(rf"^{re.escape(name)}\s+{re.escape(data)}\s*$", raw, re.M):
                problems.append(f"{arm}/{lbl}: recorded '{name} {data}' NOT found verbatim in raw")
        # 2. read count must match what the text shows
        atts = attempts_of(raw)
        seen = sum(1 for a in atts if re.search(r"^\S[^\n]*\s+[0-9A-F]{4,}\s*$", a, re.M))
        if r.get("n_read") is not None and seen != r["n_read"]:
            notes.append(f"{arm}/{lbl}: n_read={r['n_read']} but {seen} result lines parsed")
        # 3. no attempt may decode DIFFERENTLY from another
        pairs = set()
        for a in atts:
            # ⚠ FIRST MATCH ONLY, mirroring rfid_read. See blind spot 1 in the docstring.
            m = re.search(r"^([A-Za-z0-9/\-\. ]+?)\s+([0-9A-F]{4,})\s*$", a, re.M)
            if m:
                pairs.add((m.group(1).strip(), m.group(2)))
        if len(pairs) > 1:
            problems.append(f"{arm}/{lbl}: MULTIPLE DISTINCT DECODES in one record: {sorted(pairs)}")

# 4. cross-arm agreement, derived from the raw text rather than from the stored verdict
print("=" * 78)
print(f"{'protocol':17s} {'pos':5s} {'base decode':30s} {'fixed decode':30s}")
for lbl in base:
    b, f = base[lbl], fixed.get(lbl)
    if not f:
        problems.append(f"{lbl}: present in base, ABSENT in fixed"); continue
    bd = f"{b.get('got_name')} {b.get('got_data')}"
    fd = f"{f.get('got_name')} {f.get('got_data')}"
    flag = "" if bd == fd else "   <<< DIFFERS"
    if bd != fd: problems.append(f"{lbl}: decode differs: {bd} vs {fd}")
    if b.get("position") != f.get("position"):
        problems.append(f"{lbl}: position differs {b.get('position')} vs {f.get('position')}")
    if b.get("pm3_clone") != f.get("pm3_clone"):
        problems.append(f"{lbl}: clone command differs between arms")
    print(f"{lbl:17s} {str(b.get('position')):5s} {bd[:30]:30s} {fd[:30]:30s}{flag}")
for lbl in fixed:
    if lbl not in base: problems.append(f"{lbl}: present in fixed, ABSENT in base")

# 5. is each identity claim independently justifiable from the clone command?
print("\n" + "=" * 78)
print("IDENTITY BASIS, re-derived from the clone command with fresh code")
ARG = re.compile(r"--(fc|cn|id|uid|country|national|raw)\s+([0-9A-Fa-fx]+)|(?:^|\s)-r\s+([0-9A-Fa-f]+)")
weak = []
for lbl, r in sorted(base.items()):
    clone, raw, data = r.get("pm3_clone", ""), r.get("raw") or "", r.get("got_data") or ""
    if clone.startswith("T55XX:"):
        blocks = clone.split(":", 1)[1].split(",")
        dump_ok = all(b.upper() in (r.get("pm3_out") or "").upper() for b in blocks)
        basis = f"block readback {'OK' if dump_ok else 'NOT CONFIRMED'} ({len(blocks)} words)"
        if not dump_ok: problems.append(f"{lbl}: T55XX blocks not all present in the dump")
        # the pinned value must be traceable to the tag, not just to itself
        if data and data not in raw: problems.append(f"{lbl}: pinned data absent from raw")
        weak.append((lbl, "pinned from observed round trip (encoder = decoder)", basis))
        continue
    vals = [v for t in ARG.findall(clone) for v in t[1:] if v]
    def traceable(v):
        """Does the value we ASKED for appear anywhere in the Flipper's own output, in any of the
        forms the two tools legitimately differ by (padding, hex vs decimal)?"""
        forms = {v, v.upper(), v.lstrip("0") or "0"}
        if v.isdigit():
            forms.add(str(int(v)))
        if re.fullmatch(r"[0-9A-Fa-f]+", v):
            try: forms.add(str(int(v, 16)))
            except ValueError: pass
        up = raw.upper()
        return any(f and f.upper() in up for f in forms)
    # a payload SLICE counts: the Flipper often renders part of the raw (nexwatch)
    def sliced(v):
        return len(data) >= 4 and (data.upper() in v.upper() or v.upper() in data.upper())
    hits = [v for v in vals if traceable(v) or sliced(v)]
    # and a pinned table expectation counts when it is independently derivable
    pin = (r.get("want") or {})
    if not hits and pin:
        if all(str(pv).upper() in raw.upper() for pv in pin.values()):
            hits = ["<table pin present in output>"]
    print(f"  {lbl:17s} asked {str(vals):44s} -> {len(hits)}/{len(vals)} traceable in the Flipper's own output")
    if vals and not hits:
        problems.append(f"{lbl}: NOTHING we asked for is visible in the Flipper output")

print("\n" + "=" * 78)
if weak:
    print("ROWS WHOSE IDENTITY IS WEAKER BY CONSTRUCTION (must be stated, not hidden):")
    for lbl, why, basis in weak: print(f"  {lbl:17s} {why}\n{'':19s} {basis}")
print("\n" + "=" * 78)
print(f"HARD PROBLEMS: {len(problems)}")
for p in problems: print("  ⛔", p)
print(f"\nNOTES: {len(notes)}")
for n in notes[:12]: print("  ⚠", n)
