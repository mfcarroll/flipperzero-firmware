#!/usr/bin/env python3
"""Measure the LF capture latency bias `L` on a Flipper Zero, before and after the
furi_hal_rfid exact-period patch. Standalone: needs only pyserial and a Flipper on USB.

    python3 measure_capture_latency.py <label> <captures> <out.json>      # per phase
    python3 measure_capture_latency.py --compare base1.json,base2.json fixed.json

WHY IT LOOKS LIKE THIS -- three non-obvious things, each of which produced a wrong answer first:

1. RUN THE BASELINE TWICE, BRACKETING THE PATCHED BUILD. Between two measurements of IDENTICAL
   firmware 25 minutes apart, the reported HIGH width drifted 0.5us and the derived LOW 0.6us --
   larger than the residual that drift was masquerading as. The PERIOD comes from the tag's own
   clock and is stable (0.1us); the HIGH depends on envelope shape and threshold, which is analogue
   and drifts. Pooling two baselines that bracket the patched run cancels it.

2. CLUSTER, DO NOT AVERAGE. `rfid raw_read` returns a fixed ~71 pairs per capture whatever duration
   you ask for, and the OVERALL mean period swings +/-1.4us with where in the tag's bit pattern the
   capture began -- the same size as the effect. Take the mean of the dominant value cluster, with
   the window centred on the data's own mode (a FIXED window silently truncates asymmetrically once
   the distribution moves between builds).

3. THE STANDARD ERROR IS NOT THE ERROR BAR. It measures within-run scatter and cannot see the
   between-run systematic in (1). Eight times the samples made a wrong answer MORE significant
   (2 sigma -> 6 sigma) because more data shrinks SE while leaving a systematic untouched. The
   same-build repeat is what exposes it; collecting more of one arm never will.

CONTROL: low = period - high. `L` cancels in that subtraction, so it must NOT shift between builds.
If it does, something other than the capture origin changed and the result is not interpretable.
"""
import sys, glob, time, re, json, statistics
from collections import Counter

CLUSTER_HALFWIDTH = 12          # us; cluster spread is ~4us, so this contains it either way
CAPTURE_SECONDS   = 2.5         # raw_read needs ~2s to start; shorter yields nothing


def open_port():
    import serial                                    # pyserial
    paths = glob.glob('/dev/cu.usbmodemflip_*') or glob.glob('/dev/cu.usbmodem*') \
        or glob.glob('/dev/ttyACM*')
    if not paths:
        sys.exit("no Flipper serial port found")
    s = serial.Serial(paths[0], 115200, timeout=0.2, write_timeout=10)

    def read_until_quiet(gap=1.0, cap=45):
        """`raw_analyze` prints every pair -- hundreds of KB. A half-drained buffer makes the NEXT
        command parse leftovers, which is how a physically impossible 172us mean once appeared."""
        buf, last, t0 = b"", time.time(), time.time()
        while time.time() - t0 < cap:
            c = s.read(4096)
            if c:
                buf += c; last = time.time()
            elif time.time() - last > gap:
                break
            else:
                time.sleep(0.02)
        return buf.decode("utf-8", "replace")

    return s, read_until_quiet


def capture(runs, label):
    s, drain = open_port()
    pairs, found = [], 0
    for i in range(runs):
        s.reset_input_buffer(); drain(0.5, 5)
        s.write(f"rfid raw_read ask /ext/m{i % 4}.raw\r".encode()); s.flush()
        time.sleep(CAPTURE_SECONDS)
        s.write(b"\x03"); s.flush(); drain(1.0, 10)              # Ctrl+C stops raw_read
        s.write(f"rfid raw_analyze /ext/m{i % 4}.raw\r".encode()); s.flush()
        out = drain(1.5, 45)
        found += len(re.findall(r"<FOUND ", out))
        for ln in out.splitlines():
            m = re.match(r"\s*\[(\d+)\s+(\d+)\]\s+\[(\d+)\s+(\d+)\]", ln)
            if m:
                pairs.append((int(m.group(1)), int(m.group(2))))   # (high, period)
        sys.stdout.write("."); sys.stdout.flush()
    print()
    if not found:
        print("⚠ NO decode found in any capture -- is a tag on the pad? Results are meaningless.")
    return {"label": label, "runs": runs, "found": found, "pairs": pairs}


def cluster(vals):
    mode = Counter(vals).most_common(1)[0][0]
    sel = [v for v in vals if abs(v - mode) <= CLUSTER_HALFWIDTH]
    sd = statistics.stdev(sel) if len(sel) > 1 else 0.0
    return statistics.mean(sel), sd, (sd / len(sel) ** 0.5 if len(sel) > 1 else 0.0), len(sel)


def quantities(pairs):
    return {"period": [p for _, p in pairs],
            "high":   [h for h, _ in pairs],
            "low":    [p - h for h, p in pairs]}


def report(name, pairs):
    print(f"{name:26s} pairs={len(pairs)}")
    for k, v in quantities(pairs).items():
        m, sd, se, n = cluster(v)
        print(f"   {k:7s} mean={m:8.3f}  sd={sd:5.3f}  SE={se:5.3f}  n={n}")
    return quantities(pairs)


def main():
    if sys.argv[1] == "--compare":
        base = [tuple(x) for f in sys.argv[2].split(",") for x in json.load(open(f))["pairs"]]
        fixd = [tuple(x) for x in json.load(open(sys.argv[3]))["pairs"]]
        qa, qb = report("baseline (pooled)", base), report("patched", fixd)
        print()
        for k in ("period", "high", "low"):
            ma, _, sea, _ = cluster(qa[k]); mb, _, seb, _ = cluster(qb[k])
            d, sd = mb - ma, (sea ** 2 + seb ** 2) ** 0.5
            tag = "   <- CONTROL, must be ~0" if k == "low" else ""
            print(f"  {k:7s} {d:+8.3f} +/- {sd:5.3f}   {abs(d)/sd if sd else 0:5.1f} sigma{tag}")
        return
    label, runs, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    d = capture(runs, label)
    json.dump(d, open(out, "w"))
    print(f"=== {label}: {d['runs']} captures, {d['found']} decodes, {len(d['pairs'])} pairs -> {out}")
    report(label, [tuple(x) for x in d["pairs"]])


if __name__ == "__main__":
    main()
