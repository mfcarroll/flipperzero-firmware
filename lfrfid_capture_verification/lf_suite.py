#!/usr/bin/env python3
"""LF protocol regression suite -- drives the Flipper CLI, one record per (build, protocol, step).

Design: LF_REGRESSION_SUITE_DESIGN.md. Purpose: prove a furi_hal_rfid change leaves every LF protocol
decoder's verdict IDENTICAL. Pass is "same answer as the baseline build", not "still works".

⚠ TRANSPORT IS REUSED, NOT REIMPLEMENTED. t5577_campaign.open_port/run_cmd carry a byte-drop guard; a
naive tty reader silently loses characters under load and makes a firmware bug look like a decoder bug.

⚠ `rfid read` BLOCKS FOREVER and expects Ctrl+C. Everything about this file's read primitive exists for
that: send the command, watch for the result line, and on deadline send ETX (0x03) so the CLI returns to
the prompt -- otherwise the NEXT command is swallowed by the still-running read and every subsequent
result is attributed to the wrong protocol. A timeout is scored NO_READ, which is NOT a wrong answer and
must never be compared as one.

    python3 lf_suite.py --expect-commit <sha> --build <label> [--only HIDProx] [--out records.json]
"""
import argparse, json, os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import t5577_campaign as camp

# --- the subset: chosen to span both read front ends and a wide range of bit rates, because a timing
# --- change is sensitive to modulation and clock, not to data format. Extend to the full 22 later.
# ⚠ EVERY TAG IS A T5577, because that is the only writable LF silicon in the kit. What that covers fully:
# protocol, bit rate, modulation, frame structure -- a configured T5577 emits a conformant waveform, which
# is the premise `lf <proto> clone` rests on. What it covers only PARTIALLY: the analog envelope, since
# every sample comes from a T5577 modulator. A native EM4100 or HID chip could have different edge shape or
# modulation depth, and envelope shape demonstrably matters to this front end (the de-stretch offset, HIGH
# merging). Residual risk for THIS patch is small -- it removes a constant measurement error and does not
# alter envelope shape -- but the honest statement is "T5577-sourced waveforms only", and it belongs in the
# upstream report rather than being left for a reviewer to notice.
#
# ⭐ ONE TAG, REPROGRAMMED PER PROTOCOL -- the operator's design and it is better than programming a set
# and labelling them. Two reasons: (1) the tag's contents are VERIFIED on the PM3 immediately before the
# Flipper reads it, closing the gap that let a stale tag waste an hour of this project's time; (2) running
# the whole matrix on a different silicon is just "swap the one tag and re-run", so `--silicon` is a
# run-level label. It also removes physical labelling, and with it a whole class of human error.
#
# ⭐ SILICON DIVERSITY IS FREE: the kit has TWO vendors, Silicon Craft 0x39 (white coins, copper coins)
# and Invengo 0x45 (the dual fobs' LF die). Run the matrix once per vendor.
#
# ⛔ DO NOT USE THE ORANGE FOBS AS SUITE CARRIERS. Operator-confirmed: blocks 3-6 do not work on that
# silicon, so a protocol whose frame needs the upper blocks cannot be written to them at all. That
# failure arrives looking exactly like a decoder fault -- PM3 clones "successfully", the Flipper reads
# nothing -- and it would be charged to the firmware. Most LF protocols fit in blocks 1-2, so an orange
# fob will PASS most rows and fail a few for a reason that has nothing to do with what we are testing.
# A carrier that fails selectively for storage reasons is worse than one that fails outright.
# Rows the PROXMARK writes block by block, for the protocols whose encoder the Proxmark client does
# not have. The block words are bootstrapped ONCE, OUT OF BAND: write the tag on the Flipper by hand,
# read it back with `lf t55xx detect` + `lf t55xx dump`, and paste the words in here. That happens
# once per protocol ever, so it has no business in the run loop -- an earlier version drove the GUI
# mid-run, and the LF RFID app (which holds the LF worker for as long as it is open) wedged the CLI
# and hung the whole pass on a one-byte write. Once a recipe exists the row is ORDINARY: the Proxmark
# programs it, the Flipper reads it, and every existing guard applies unchanged -- including
# CLONE_MISMATCH, which for these rows compares the block words themselves.
T55XX_PREFIX = "T55XX:"

SUBSET = [
    # ⚠ THE "PM3 verify must contain" STRINGS ARE READ OFF THE PROXMARK CLIENT SOURCE, NOT GUESSED.
    # Guessing produced two wrong ones -- "EM410x" (the source prints "EM 410x ID ", WITH spaces) and
    # "ioProx" (it prints "IO Prox - ") -- and a wrong expect string surfaces as a FALSE BENCH FAULT that
    # short-circuits the protocol, i.e. it looks like the tag failed to program. Verify against
    # proxmark3/client/src/cmdlf<proto>.c, in the demod<Proto>() the `lf search` path calls.
    #   demodEM410x  -> "EM 410x ID "        demodAWID   -> "AWID - len: "
    #   demodIOProx  -> "IO Prox - "         demodViking -> "Viking - Card "
    #   demodPac     -> "PAC/Stanley - Card: "
    # HID and Indala print via a table; confirmed from real output: "[H10301 ] HID H10301 26-bit" and
    # "[ind26  ] Indala 26-bit".
    # ⚠ THE 5TH COLUMN IS THE IDENTITY CHECK, and it is the difference between "a protocol was
    # recognised" and "the RIGHT CARD was read". Name-only matching would pass a decoder that returned a
    # plausible wrong ID -- exactly the failure class this project has spent days on. We can assert it
    # because WE chose the clone parameters, so the expected values are known, not inferred.
    # Empty dict = identity not yet pinned for that protocol; those are weaker rows and are reported as
    # NAME-ONLY rather than silently counted as full passes.
    # ⚠ THE 6TH COLUMN IS AN EXACT AIR GAP, standardised on the operator's call: 6mm for most,
    # 3mm for indala26, 9mm for em4100_16. One number per protocol, not a range, so the recorded
    # position is the height actually used and two runs can be compared without argument.
    # The windows behind those choices: Six of the eight read anywhere from 3 to
    # 9 mm. The other two want OPPOSITE things and their windows barely meet: em4100_16 (ASK RF/16) is 0/5
    # at 7 mm and 5/5 at 8 mm; indala26 (PSK) reads at 3-6 mm and 0/3 at 9 mm. So there is no robust
    # universal height -- any overlap is ~1 mm wide, which nobody can reproduce -- and pretending otherwise
    # would hand a maintainer a setup that fails on them.
    # label          Flipper name    PM3 clone command                              PM3 verify     expected identity          air gap
    # ⚠ H10301 and HIDProx are DIFFERENT protocols in the dict: H10301 is the 26-bit format, HIDProx is
    # hid_generic (longer raws). A 26-bit raw decodes as H10301. Getting this wrong cost a spurious
    # "PROTOCOL MISMATCH" on the first successful read of the suite.
    # ⚠ AMBIGUITY, NOT A BUG: PM3 reports this same raw as matching BOTH H10301 and Indala 26-bit
    # ("found 2 matching 26-bit formats"). The Flipper picks H10301. Do not score a fork that picks
    # Indala26 here as a failure -- it is the same bits under a different reading.
    # ⚠ ORDER IS DELIBERATE: the six 6mm protocols first, then 3mm, then 9mm. Sorting by gap turns
    # four height changes into TWO, and a height change is the step most easily missed -- a protocol
    # read at the wrong gap produces a false NO_READ that looks like a firmware result.
    ("em4100",      "EM4100",     "lf em 410x clone --id 1122334455",              "EM 410x",     {"data": "1122334455"}, "6mm"),
    ("hid_h10301",  "H10301",     "lf hid clone -r 2006175c6f",                    "H10301",      {"FC": "11", "Card": "44599"}, "6mm"),
    ("ioprox",      "IoProxXSF",  "lf io clone --vn 1 --fc 101 --cn 1337",         "IO Prox",     {"FC": "101", "Card": "1337"}, "6mm"),
    ("awid",        "AWID",       "lf awid clone --fmt 26 --fc 101 --cn 1337",     "AWID",        {"FC": "101", "Card": "1337"}, "6mm"),
    ("viking",      "Viking",     "lf viking clone --cn 0001A337",                 "Viking",      {}, "6mm"),
    ("pac_stanley", "PAC/Stanley","lf pac clone --cn CD4F5552",                    "PAC/Stanley", {}, "6mm"),
    # --- expanded 2026-08-21: flashing costs ~6 min, a protocol costs two tag moves, so test everything.
    # Clone syntax and demod strings read from proxmark3/client/src/cmdlf*.c. ⚠ Flipper calls securakey
    # "Radio Key" -- a name mismatch would look like a decoder fault. A WRONG clone guess is safe here:
    # it fails the PM3 verify and reports a BENCH FAULT rather than a false regression.
    # ⭐ This brings in PYRAMID, which with EM4100 and PAC/Stanley completes the three decoders that
    # actually differ between OFW, Unleashed and Momentum -- the rows where a fork difference could show.
    ("em4100_32",   "EM4100/32",  "lf em 410x clone --id 1122334455 --clk 32",     "EM 410x",     {"data": "1122334455"}, "6mm"),
    ("fdx_b",       "FDX-B",      "lf fdxb clone --country 999 --national 1337",   "Animal ID",   {}, "6mm"),
    # ⚠⚠ --xor 141 IS LOAD-BEARING, NOT COSMETIC, and --xor 0 cost four runs. GProxII is ASK/BIPHASE,
    # which recovers its clock from transitions, and the xor is applied to every byte of the frame --
    # so it acts as a WHITENER, not merely obfuscation. With --xor 0 the XOR is a no-op and the blocks
    # come out F8001320/0002D840/8D201800: a structurally VALID frame (preamble 111110 present, and
    # the Proxmark reports "Data written and verified") that is nonetheless physically undemodulable,
    # because those long uniform runs give biphase nothing to clock off. With 141 the same card number
    # writes FAC2A38C/2B081AF0/210B12C2 and both `lf gproxii reader` and `lf search` read it first try.
    # 141 is the Proxmark's own documented example value (cmdlfguard.c:"lf gproxii clone --xor 141").
    # ⚠ I ALSO MIS-DIAGNOSED THIS TWICE: first as a wrong subcommand name, then as `lf search` not
    # scanning for G-Prox-II. It scans for it fine. Both were inferences from "No known tags found"
    # rather than from running the command -- which the operator's rig answered in one shot (§7.43).
    ("gproxii",     "GProxII",    "lf gproxii clone --xor 141 --fmt 26 --fc 123 --cn 1337", "G-Prox-II", {}, "6mm"),  # ⚠ command is gproxii, file is cmdlfguard.c
    ("idteck",      "Idteck",     "lf idteck clone --raw 4944544B351FBE4B",        "IDTECK",      {}, "6mm"),
    ("noralsy",     "Noralsy",    "lf noralsy clone --cn 112233",                  "Noralsy",     {}, "6mm"),
    ("paradox",     "Paradox",    "lf paradox clone --fc 96 --cn 40426",           "Paradox",     {}, "6mm"),
    ("nexwatch",    "Nexwatch",   "lf nexwatch clone --raw 5600000000213C9F8F150C00", "NexWatch", {}, "6mm"),
    ("pyramid",     "Pyramid",    "lf pyramid clone --fc 123 --cn 11223",          "Pyramid",     {}, "6mm"),
    ("jablotron",   "Jablotron",  "lf jablotron clone --cn 01b669",                "Jablotron",   {}, "6mm"),
    ("securakey",   "Radio Key",  "lf securakey clone --raw 7FCB400001ADEA5344300000", "Securakey", {}, "6mm"),
    # --- expanded 2026-08-21 (second pass): the last four protocols the PROXMARK can write ---------
    # Clone syntax and demod strings read from proxmark3/client/src/cmdlf*.c, not guessed:
    #   cmdlfgallagher.c:177  "lf gallagher clone --rc 0 --fc 9876 --cn 1234 --il 1"
    #   cmdlfgallagher.c:88   prints "GALLAGHER - Region: .. Facility: .. Card No.: .."
    #   cmdlfdestron.c:141    "lf destron clone --uid 1A2B3C4D5E"
    #   cmdlfdestron.c:89     prints "FDX-A FECAVA Destron: <5 bytes>"
    #   cmdlfhid.c:410        "-r 2e0ec00c87 -> HID Corporate 35 bit"; the format table row is C1k35s
    #                         (wiegand_formats.c:1576). 26-bit raws decode as H10301, 35-bit as HIDProx.
    #   cmdlfindala.c:796     the 56-hex-char raw is auto-detected as 224-bit (cmdlfindala.c:877)
    # ⚠ Flipper names differ from Proxmark names for two of these: FDX-A is Proxmark's "destron",
    # and hid_generic renders as "HIDProx". A name mismatch here would read as a decoder fault.
    # Identity is left to the DERIVED check rather than pinned in column 5 -- clone_expectation now
    # reads --uid and -r, so gallagher (--fc/--cn), fdx_a (--uid) and indala224 (-r) all carry their
    # own ground truth. Pinning a value I have not yet observed is how false BENCH FAULTS get made.
    ("gallagher",   "Gallagher",  "lf gallagher clone --rc 0 --fc 9876 --cn 1234 --il 1", "GALLAGHER", {}, "6mm"),
    ("fdx_a",       "FDX-A",      "lf destron clone --uid 1A2B3C4D5E",             "FDX-A FECAVA Destron", {}, "6mm"),
    ("hid_generic", "HIDProx",    "lf hid clone -r 2e0ec00c87",                    "C1k35s",      {}, "6mm"),
    # ─── T55XX ROWS: block words bootstrapped once, out of band (see T55XX_PREFIX) ───────────────
    # electra, 2026-08-21: written on the Flipper as data A55AC33CA55AC33C, then read back with
    # `lf t55xx detect` + `lf t55xx dump`. Config 00148080 decodes as RF/64, Manchester, MAXBLOCK=4
    # (0x80 & 0xE0 >> T55x7_MAXBLOCK_SHIFT=5), so the frame is blocks 1-4 and anything in 5-7 is
    # outside it -- the dump showed B3C6AD1F/CF649393/928C14E5 there, the tail of the earlier
    # indala224 raw, which the tag simply does not transmit. Decode method cross-checked against
    # gproxii's 00150060, which gives MAXBLOCK=3 and matches its `3 << T55x7_MAXBLOCK_SHIFT` source.
    # Write+readback verified on the physical tag before this row was added.
    # ⭐ PINNED FROM AN OBSERVED ROUND TRIP (10/10, 2026-08-21): the full 8 bytes entered on the Flipper
    # came back verbatim as A55AC33CA55AC33C, so the encoder does not recompute or mask anything here
    # and the value is a legitimate regression expectation. want{} was empty on the first pass precisely
    # so this could be measured rather than asserted -- pinning an unobserved round trip is how false
    # BENCH FAULTS get made, and a rescore upgrades the row for free once the evidence exists.
    ("electra",     "Electra",    T55XX_PREFIX + "00148080,FFD14AA6,0C6C515E,5AC33C3C,3C3C3C3C", "",
     {"data": "A55AC33CA55AC33C"}, "6mm"),
    # insta_fob, 2026-08-21: the Flipper's write DID land -- dump showed exactly what its write_data
    # specifies. Block 0 000880E8 = Manchester | RF/32 | ST | MAXBLOCK=7.
    # ⚠ MAXBLOCK=7, SO BLOCKS 3-7 ARE PART OF THE TRANSMITTED FRAME even though they are zero, and
    # they are written explicitly for that reason. electra's recipe stops at block 4 because its
    # MAXBLOCK is 4 -- the frame length is a property of block 0, not of how much data looks useful.
    # ⚠ AND THE PAYLOAD IS NOT WHAT YOU TYPE. protocol_insta_fob_encoder_start compares the first four
    # bytes against the fixed INSTAFOB_BLOCK1 (0x00107060) and OVERWRITES them if they differ, so only
    # the last four bytes of the entered value survive. Do not read block 1 as evidence of anything we
    # chose; want{} stays empty until a read is observed.
    # ⭐ PINNED FROM AN OBSERVED ROUND TRIP (10/10, 2026-08-21): 001070605AA53CC3 -- blocks 1 and 2
    # concatenated, i.e. the forced INSTAFOB_BLOCK1 constant followed by the only four bytes of the
    # entered value that survive encoder_start. Note this does NOT match what the operator typed, and
    # that is correct rather than a fault: see the mutation note above.
    ("insta_fob",   "InstaFob",   T55XX_PREFIX + "000880E8,00107060,5AA53CC3,00000000,00000000,00000000,00000000,00000000", "",
     {"data": "001070605AA53CC3"}, "6mm"),
    # hid_ex_generic, 2026-08-21: block 0 001070C0 = FSK2a | RF/50 | MAXBLOCK=6, no ST -- exactly what
    # protocol_hid_ex_generic_write_data specifies, and 6 blocks x 32 = 192 = HID_ENCODED_BIT_SIZE.
    # Block 7 read back as zero and is OUTSIDE the frame, so it is not in the recipe (cf. insta_fob,
    # where MAXBLOCK=7 makes the zeros load-bearing). The operator reported this one as intermittent
    # to write from the GUI; the Proxmark writes it deterministically from here on.
    # ⚠ HIDExt renders a HARDCODED "Type: Generic HID Extended / Data: Unknown" (TODO FL-3518), so this
    # row can only ever be NAME-ONLY. It still answers the question being asked -- same bits, both
    # builds, same decode -- but it cannot contribute an identity check, and should not be counted as one.
    # ⭐ PINNED FROM AN OBSERVED ROUND TRIP (10/10, 2026-08-21), AND THE ONE ALTERED NIBBLE IS EXPLAINED.
    # Entered A55AC33C96693CC3A55A6996, read back A55AC33C96693CC3A55A6990 -- the final nibble 6 -> 0.
    # That is not corruption: HID_DECODED_BIT_SIZE is 92 ((192 - 8) / 2) while HID_DECODED_DATA_SIZE is
    # 12 bytes = 96 bits, so bits 92-95 are outside the payload and render as zero. Exactly one nibble,
    # exactly where the arithmetic puts it. Pinning the OBSERVED value rather than the entered one is
    # correct here; pinning what I typed would have manufactured a permanent false WRONG_ID.
    ("hid_ex_generic", "HIDExt",  T55XX_PREFIX + "001070C0,1D996666,99A55A5A,A5966969,965AA5A5,5A996666,99699696", "",
     {"data": "A55AC33C96693CC3A55A6990"}, "6mm"),
    # ⭐⭐ TWO EM4100 IDs ON ONE TAG -- the configuration that Unleashed #1024 reported as HANGING on
    # Read, added because reviewing WHY the forks diverged pointed straight at it (findings doc §12).
    # ID A 1122334455 in blocks 1-2, ID B AABBCCDDEE in blocks 3-4, MAXBLOCK=4, so the tag emits TWO
    # EM4100 frames per cycle. Since the Electra work (a86aeface) the EM4100 decoder requires the NEXT
    # frame's header as a lookahead, and with a 64-bit lookahead a two-frame tag locked into A/B
    # alternation and never produced the three identical decodes Read requires.
    # ⚠ THE BLOCK WORDS ARE VALIDATED, NOT DERIVED-AND-HOPED. My host-side EM4100 encoder produced
    # FF8C65298C94A940 for ID A, and the Proxmark independently printed "Encoded to FF 8C 65 29 8C 94
    # A9 40" for the same ID, with `lf t55xx dump` confirming blocks 1-2 on the physical tag. Config
    # 00148080 (Manchester | RF/64 | MAXBLOCK=4) matches the real Electra tag's config, which is also a
    # four-block EM4100-family frame. Writing an unvalidated frame is the gproxii --xor 0 mistake.
    # ⚠ EITHER ID IS A LEGITIMATE ANSWER -- which one the decoder settles on is not determined a
    # priori -- so want{} stays empty and the INSTRUMENT FOR THIS ROW IS THE INCONSISTENT DETECTOR:
    # the fix means three identical decodes, and A/B alternation means the framing broke.
    # ⚠ EXPECTED TO FAIL ON OFW AND MOMENTUM, on BOTH arms, because they still carry the 64-bit
    # lookahead. That is the pre-existing upstream bug, scores UNSCORED, and is NOT ours. It has teeth
    # on UNLEASHED, the tree where this configuration is supposed to work.
    # ⚠⚠ BOTH IDS ARE CORRECT ANSWERS, and want{} alone got this wrong. Measured on unlshd-092:
    # 10/10 reads, returning 1122334455 on some attempts and AABBCCDDEE on others -- and the
    # INCONSISTENT detector fired, because the row was written as though one answer were expected.
    # It is not a defect: the tag really does hold two frames and a read syncs on whichever it finds
    # first. Unleashed's fix restores three identical decodes WITHIN one read; which frame a SEPARATE
    # read lands on was never specified by it, and I conflated the two.
    # ⇒ any_of declares the legitimate answer set. INCONSISTENT is still raised for anything OUTSIDE
    # it -- a value that is neither id would be a real finding, and that detector must not be blunted.
    ("em4100_multi", "EM4100",    T55XX_PREFIX + "00148080,FF8C6529,8C94A940,FFD297BE,31BDF7A0", "",
     {"any_of": ["1122334455", "AABBCCDDEE"]}, "6mm"),
    # ⚠ keri IS 3mm TOO, and 6mm was never validated. It read 1/3 at 6mm on BOTH builds -- the only
    # row in the matrix that was never a reliable reader -- and I reported that inside a "complete"
    # pass instead of asking why. The operator asked. Swept on the no-fix build: 10/10 at 3mm against
    # 1/3 at 6mm, so it is positional, exactly like indala224. Moved next to the other 3mm rows.
    # ⚠ CONSEQUENCE FOR THE EXISTING RESULT: both Momentum arms captured keri at 6mm, so for that one
    # row "26 SAME" rests on two WEAK measurements agreeing (1/3 vs 1/3) rather than two solid ones.
    # Re-running keri on both Momentum arms at 3mm is one protocol per arm and would upgrade it.
    ("keri",        "Keri",       "lf keri clone -t i --cn 12345",                 "KERI",        {}, "3mm"),
    # ⚠⚠ indala224 IS 3mm, NOT 6mm, AND THE 6mm DATA WAS GEOMETRY MASQUERADING AS A FIRMWARE EFFECT.
    # It read 0/10 twice at 6mm on the NO-FIX build and 2/3 at 6mm on the fixed one, which surfaced as a
    # GAINED_READ -- i.e. as though the capture fix had rescued the protocol. A gap sweep on the
    # BASELINE settled it: 10/10 at 3mm, 10/10 at 4mm, 0/10 at 5mm, 0/20 at 6mm. The baseline reads this
    # protocol perfectly; 6mm is simply outside its window, which is TIGHTER than indala26's 3-6mm even
    # though both are Indala. Placed next to indala26 so the run still has only two height changes.
    # ⇒ Any 6mm record for this row is measurement from outside the readable window and must not be
    # compared against a 3mm one. The position guard enforces that; it does not need remembering.
    ("indala224",   "Indala224",  "lf indala clone -r 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5", "Indala", {}, "3mm"),
    ("indala26",    "Indala26",   "lf indala clone --heden 888",                   "Indala",      {}, "3mm"),   # window 3-6mm: 0/5 at 8mm, 0/3 at 9mm
    ("em4100_16",   "EM4100/16",  "lf em 410x clone --id 1122334455 --clk 16",     "EM 410x",     {"data": "1122334455"}, "9mm"),   # window 8-12mm: 0/5 at 3 and 7mm, 5/5 at 8, 10/10 at 9
]

# ⚠ REUSE THE CUE VOCABULARY, do not invent a second one. t5577_campaign._cue already keys sounds and
# speech off "[PM3]" / "[Flipper]" markers -- Submarine/"Proxmark", Glass/"move to Flipper",
# Tink/"reposition" -- and the operator has those associations trained. A new set of noises for the same
# actions would be actively worse than silence. In the phase-split flow the cue announces the NEXT
# PHYSICAL ACTION, because the operator is not watching the terminal during a run.
def cue_move_to_flipper(what=""):
    camp._cue(f"[Flipper] {what}")


def cue_move_to_pm3(what=""):
    camp._cue(f"[PM3] {what}")


def cue_done(words, sound):
    """End-of-run announcement. Sound + spoken summary, BLOCKING like cue_fault.

    ⚠ ONLY FAILURES USED TO ANNOUNCE THEMSELVES, so a clean run ended in silence -- and a 26-protocol
    pass is exactly when the operator has wandered off to do something else. Silence is not a neutral
    default here: it is indistinguishable from the run still going, and this suite has already had a
    healthy pass killed by hand because a slow miss looked like a hang.
    ⚠ THREE OUTCOMES, THREE SOUNDS, because "it stopped" is not the useful bit -- whether it needs the
    operator back at the bench is. Hero for a clean pass, Sosumi for finished-but-incomplete, and
    cue_fault's Basso for real failures.
    """
    import subprocess
    sys.stdout.write("\a")
    sys.stdout.flush()
    try:
        subprocess.Popen(["afplay", "/System/Library/Sounds/%s.aiff" % sound],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    try:
        subprocess.run(["say", "-r", "200", words], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
    except Exception:
        pass


def cue_fault(words):
    """Basso + speech, matching the campaign harness's fault cue. A bench fault the operator does not
    hear is a bench fault they discover ten protocols later."""
    # ⚠ BLOCKING, deliberately. Popen here meant the fault speech and the NEXT prompt's cue played at
    # the same time -- two voices at once, so the operator heard neither. An error path is exactly where
    # a couple of seconds of waiting is free, and where being heard matters most.
    import subprocess
    sys.stdout.write("\a")
    sys.stdout.flush()
    try:
        subprocess.Popen(["afplay", "/System/Library/Sounds/Basso.aiff"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    try:
        subprocess.run(["say", "-r", "220", words], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
    except Exception:
        pass


RESULT_RE = re.compile(r"^([A-Za-z0-9/\-\. ]+?)\s+([0-9A-F]{4,})\s*$", re.M)
# The decoder also renders human fields after the hex ("FC: 11", "Card: 44599"). Those are what the PM3
# prints too, so they are the directly comparable quantity across the two implementations -- capture them.
# ⚠⚠ TWO FIELDS CAN SHARE A LINE. This was anchored ^...$, i.e. one key:value per whole line, and
# pyramid renders `FC: %03hhu; Card: %05hu` -- BOTH fields on one line, semicolon-separated. So the
# only row in the matrix that never got an identity check was not a firmware limitation at all: the
# Flipper printed "FC: 123; Card: 11223", exactly what we cloned, and this regex matched neither of
# them while happily matching "Format: 26" on the line above. It reported NAME-ONLY -- a check that
# silently declined to check -- and I twice wrote that up as the Flipper CLI "rendering only a format
# length", from reading the report instead of the raw text three lines further down.
RENDER_RE = re.compile(r"(?:^|;)\s*([A-Za-z][A-Za-z ]{0,20}):\s*([^\s;]+)\s*(?=;|$)", re.M)


# ⭐ LEARN THE EXPECTED IDENTITY FROM THE PROXMARK, do not hardcode it. The PM3 prints the decoded
# identity when it verifies -- "Viking - Card 0001A337", "PAC/Stanley - Card: CD4F5552", "Indala 26-bit
# FC: 186 CN: 3639" -- so the suite can take it from there and hold the Flipper to it. Three reasons this
# beats a hardcoded table: it needs no prior knowledge of protocols we have never read, it cannot go stale
# when a clone parameter changes, and it makes the assertion PM3-versus-Flipper rather than
# Flipper-versus-my-guess, which is the cross-implementation check this suite exists to be.
# ⚠ The two tools name the same field differently: PM3 says CN, the Flipper says Card. Normalise, or the
# comparison silently finds no overlapping keys and passes everything.
# ⛔⛔ ONLY EVER INSPECT THE `lf search` RESULT SEGMENT. The combined output also contains the echoed
# command line ("execute command from commandline: lf viking clone --cn ... ; lf search") and the clone's
# own chatter ("Preparing to clone Viking tag..."), both of which contain the protocol name. A
# case-insensitive substring test over the whole output therefore matched EVERY protocol regardless of
# what happened -- and it did: `lf viking clone --cn 1A337` was REJECTED (Viking needs 8 hex digits), the
# tag kept the previous protocol's AWID content, and the suite still reported "program+verify: OK".
# A verify that cannot fail is not a verify. "Checking for known tags" is printed only by `lf search`,
# so it is the reliable boundary.
# Bumped whenever scoring behaviour changes, and stamped into every record. A results file that cannot
# say which version of the harness produced it cannot be re-scored safely, and this suite has already
# been through seven scoring bugs.
SUITE_REV = 46  # 46: coupling probe REMOVED -- it measured nothing and printed numbers

SEARCH_MARK = "Checking for known tags"


def pm3_search_segment(out):
    """The part of the output that is `lf search`'s verdict, or "" if it never ran."""
    i = out.rfind(SEARCH_MARK)
    return out[i:] if i >= 0 else ""


# ⚠ THE VALUE MUST NOT BE FOLLOWED BY A LETTER, and must be at least 3 chars. Without the lookahead,
# "Valid EM410x ID found!" parsed as ID='f' -- 'f' being a hex digit -- and that phantom identity then
# disagreed with every real one, reporting WRONG_ID on ioprox and pac_stanley whose fields actually
# matched perfectly. A checker that invents data is worse than one that checks nothing.
# ⚠ VALUES MAY BE COMPOSITE. FDX-B prints "Animal ID:  %04u-%012u" -- e.g. 0999-000000001337 -- while
# the Flipper renders the same identity as 999-000000001337. Stopping the value at the hyphen captured
# "999" and then declared a MISMATCH against the full string: a correct read reported as WRONG_ID.
# Longer keys are listed first so "Animal ID" is not matched as bare "ID".
# ⭐ "Raw" IS HARVESTED TOO, because for some protocols it is the ONLY comparable identity. The
# Flipper renders no named fields at all for GProxII -- just the frame -- while the Proxmark prints
# "G-Prox-II - Len: 26 FC: 123 Card: 1337 xor: 141, Raw: fac2a38c2b081af0210b12c2". Both tools agree
# on that frame byte for byte, so comparing the two full frames is the STRONGEST check available:
# no field-name mapping, no slicing, no zero-padding to argue about. Without it gproxii read
# correctly 5/10 and still scored NAME-ONLY, i.e. the check quietly declined to check.
PM3_ID_RE = re.compile(
    r"\b(Animal ID|Card number|Facility Code|FC|CN|Card|ID|CIN|Raw)\s*[:.]*\s*"
    r"([0-9A-Fa-fx][0-9A-Fa-fx\-]{2,})(?![0-9A-Za-z])")
_ALIAS = {"cn": "Card", "card number": "Card", "facility code": "FC", "id": "ID",
          "fc": "FC", "card": "Card", "cin": "Card", "animal id": "ID", "internal id": "ID", "card id": "Card",
          "card number": "Card"}  # PAC: PM3 says Card, the Flipper says CIN


def pm3_identity(out, expect=None):
    """Identity fields the PM3 reported, normalised to the Flipper's names.

    ⛔ SCOPED TO THE LINE FOR THE EXPECTED PROTOCOL, and that is not fussiness. `lf search` reports EVERY
    format a raw matches: one 26-bit HID clone prints both "[H10301] ... FC: 11 CN: 44599" AND
    "[ind26] Indala 26-bit FC: 186 CN: 3639". Parsing the whole segment grabbed whichever came first and
    compared Indala's numbers against the Flipper's H10301 reading -- reporting WRONG_ID on a protocol
    that was perfectly correct. The same bits under two readings are not two identities.
    """
    seg = pm3_search_segment(out)
    lines = [l for l in seg.splitlines() if l.strip().startswith("[+]")]
    if expect:
        match = [l for l in lines if expect.lower() in l.lower()]
        if match:
            lines = match
    def harvest(src):
        got = {}
        for line in src:
            for k, v in PM3_ID_RE.findall(line):
                # ⚠ DO NOT lstrip("0") A HEX LITERAL. "0x35" becomes "x35", which parses as nothing.
                # norm_num handles padding, so store the value intact.
                got.setdefault(_ALIAS.get(k.lower(), k), v)
        return got

    got = harvest(lines)
    # ⚠ WIDEN ONLY ON EMPTY. The scoping exists because `lf search` reports every format a raw matches
    # and the wrong one's numbers must not be used -- that produced a false WRONG_ID on H10301. But when
    # the protocol's own line carries no identity (indala prints its FC/Card on a SEPARATE line),
    # refusing to look further throws the evidence away. Empty is the only safe trigger for widening.
    # ⚠⚠ "Raw" DOES NOT COUNT AS HAVING FOUND SOMETHING. It is a supplementary key, and treating it
    # as evidence broke indala26: the Proxmark's own line is "Indala (len 64) Raw: a0000000a8922953",
    # so harvesting Raw made the scoped pass look SUCCESSFUL and suppressed the widen that used to
    # find the genuinely comparable FC/Card on the reader's separate line -- turning an
    # identity-confirmed read back into NAME-ONLY. Worse, that raw is not even comparable here: the
    # Proxmark prints the 64-bit frame while the Flipper renders the 32-bit payload 512452B8. So
    # widen whenever no NAMED identity was found, regardless of whether a frame came along with it.
    if expect and not any(k != "Raw" for k in got):
        wide = harvest([l for l in seg.splitlines() if l.strip().startswith("[+]")])
        for k, v in wide.items():
            got.setdefault(k, v)
    return got


def norm_num(v):
    """Compare 1337 to 0x539 to 00001337 without tripping over base or padding.

    ⚠ Composite identities are normalised COMPONENT-WISE: "0999-000000001337" and "999-000000001337"
    are the same identity written with different zero padding, and comparing them as strings reported a
    correct FDX-B read as WRONG_ID.
    """
    if v is None:
        return None
    t0 = str(v).strip()
    # ⚠ CHECK FOR HEX BEFORE STRIPPING ZEROS. lstrip("0") turns "0x35" into "x35", which then parses as
    # nothing -- and reported securakey's FC 0x35 as disagreeing with the Flipper's 53. Same number.
    if t0[:2].lower() == "0x":
        try:
            return int(t0, 16)
        except ValueError:
            return t0.upper()
    if "-" in t0:
        return "-".join(str(p).lstrip("0") or "0" for p in t0.split("-"))
    t = t0.lstrip("0") or "0"
    try:
        return int(t, 16) if t.lower().startswith("0x") else int(t, 10)
    except ValueError:
        try:
            return int(t, 16)
        except ValueError:
            return t.upper()


# ⭐ GROUND TRUTH IS THE CLONE COMMAND. Both tools render the same identity differently -- the Proxmark
# reports idteck as a decoded "Card ID 4963871" while the Flipper reports the raw it was given; keri is
# "Internal ID" on one side and "ID" on the other; securakey is 0x35 against 53. Comparing one display
# against the other produced three WRONG_IDs on three CORRECT reads.
# But we KNOW what we asked to be written -- `--fc 96 --cn 40426`, `--raw 7FCB...`, `--id 1122334455` --
# and that is independent of anyone's formatting choices. Check against THAT first.
CLONE_ARG_RE = re.compile(r"--(fc|cn|id|uid|raw|country|national)\s+([0-9A-Fa-fx]+)")
_ARG_TO_FIELD = {"fc": "FC", "cn": "Card", "id": "ID", "uid": "ID", "national": "Card",
                 "country": "FC"}


def clone_expectation(clone_cmd):
    """-> (fields we asked for, raw we asked for or None)."""
    # ⚠ `-r` AND `--raw` ARE THE SAME PROXMARK FLAG. The regex only knew the long form, so every
    # command written with the short one -- hid, indala224 -- silently lost its clone-command ground
    # truth and fell through to weaker PM3-vs-Flipper evidence. Normalise once here rather than
    # duplicating the alternation and having the two spellings drift apart.
    clone_cmd = re.sub(r"(^|\s)-r\s+", r"\1--raw ", clone_cmd)
    want, raw = {}, None
    for k, v in CLONE_ARG_RE.findall(clone_cmd):
        if k == "raw":
            raw = v
        else:
            want.setdefault(_ARG_TO_FIELD[k], v)
    return want, raw


def check_against_clone(clone_cmd, data, flds):
    """-> (True/False/None, why). None means no comparable evidence, which is NOT a failure."""
    want, raw = clone_expectation(clone_cmd)
    if raw and data:
        # exact, or a substring: the Flipper often renders a payload slice of the raw (nexwatch does)
        if norm_num(data) == norm_num(raw):
            return True, "clone(raw)"
        # ⚠ LENGTH FLOOR: a substring test between a 2-char field and a 10-char raw passes by
        # accident ("11" is inside "2006175C6F"). A false PASS is worse than no check at all, so
        # require enough characters for the match to mean something.
        if len(data) >= 4 and (data.upper() in raw.upper() or raw.upper() in data.upper()):
            return True, "clone(raw~)"
    shared = [k for k in want if k in flds]
    if shared and all(norm_num(want[k]) == norm_num(flds[k]) for k in shared):
        return True, f"clone({','.join(shared)})"
    # ⚠ A LABEL MISMATCH IS NOT A WRONG IDENTITY. The two tools disagree about what to call things and
    # my arg->field map cannot be right for every protocol: keri's `--cn 12345` is its INTERNAL ID, while
    # the Flipper's "Card" field holds a different derived number (12544). Comparing by label alone
    # called a correct read WRONG_ID. So before failing, check whether the value we asked to be written
    # appears under ANY rendered field -- and name which one, so the weaker match is visible.
    for k, v in want.items():
        for fk, fv in flds.items():
            if norm_num(v) == norm_num(fv):
                return True, f"clone({k}={fk})"
    # ⚠ AND THE DATA HEX COUNTS TOO, not just rendered fields. jablotron's `--cn 01b669` comes back as
    # data 000001B669 -- the same number with different padding -- and it was scored WRONG_ID purely
    # because the match was in `data` rather than in a field, which is a distinction with no meaning.
    for k, v in want.items():
        if data and norm_num(v) == norm_num(data):
            return True, f"clone({k}=data)"
    if want and flds and shared:
        return False, f"clone({','.join(shared)})"
    return None, ""


def score_identity(pm3_clone, got_name, got_data, flds, pm3_id, want):
    """-> (id_ok, id_src). id_ok None means NO COMPARABLE EVIDENCE, which is not a failure.

    ⚠⚠ ONE IMPLEMENTATION, TWO CALLERS, AND IT USED TO BE TWO IMPLEMENTATIONS THAT DRIFTED.
    The live run let the PM3-vs-Flipper field comparison OVERWRITE a passing clone-command check;
    rescore let the clone check win. idteck read 4944544B351FBE4B -- byte-identical to what we
    cloned -- and scored WRONG_ID live but READ on rescore, because the Proxmark and the Flipper
    carve that same 8-byte raw into FC/Card differently. Both readings are correct; comparing one
    tool's DISPLAY against another's is the §7.42 error, and here it manufactured a false WRONG_ID,
    which is the alarming direction. The same stored bytes must never yield two verdicts, so the
    live path and rescore both come here now.
    """
    if not got_name:
        return None, ""
    id_ok, src = None, ""
    # 1. GROUND TRUTH: what we ASKED the Proxmark to write. This outranks every other source and
    #    must never be overwritten by a weaker one.
    c_ok, c_src = check_against_clone(pm3_clone, got_data, flds)
    if c_ok is not None:
        id_ok, src = c_ok, c_src
    # 2. FALLBACK, only when the clone gave us nothing comparable: what the PM3 decoded from the
    #    same tag. Weaker, because the two tools disagree about field names and boundaries.
    # ⚠ "Raw" IS DELIBERATELY EXCLUDED FROM FIELD-NAME MATCHING, and is used only against got_data
    # below. Two tools sharing a field NAME does not mean they agree on its extent or byte order --
    # indala224 renders a "Raw" too -- and comparing one display against the other on the strength of
    # a shared label is the §7.42 error in its false-WRONG_ID direction. Equality with the full frame
    # is safe; equality with a field that merely shares a name is not.
    shared = [k for k in pm3_id if k in flds and k != "Raw"]
    if id_ok is None and shared:
        src = f"PM3({','.join(shared)})"
        id_ok = all(norm_num(pm3_id[k]) == norm_num(flds[k]) for k in shared)
    elif id_ok is None and pm3_id and got_data:
        # ⚠ NO SHARED FIELD NAMES DOES NOT MEAN NO COMPARISON. Viking: the PM3 prints
        # "Viking - Card 0001A337", the Flipper renders no named fields at all, but its DATA is
        # 0001A337 -- the very number we cloned. Agreement on the value is agreement.
        hit = [k for k, v in pm3_id.items() if norm_num(v) == norm_num(got_data)]
        if hit:
            src, id_ok = f"PM3({hit[0]}=data)", True
        elif pm3_id.get("ID"):
            src = "PM3(ID)"
            id_ok = norm_num(pm3_id["ID"]) == norm_num(got_data)
    # 3. and the pinned table expectation ANDed on top, where we have one.
    if want:
        if "any_of" in want:
            w = (got_data or "").upper() in [v.upper() for v in want["any_of"]]
        elif "data" in want:
            w = (got_data or "").upper() == want["data"].upper()
        else:
            w = all(norm_num(flds.get(k)) == norm_num(v) for k, v in want.items())
        id_ok = w if id_ok is None else (id_ok and w)
        src = (src + "+table").lstrip("+")
    return id_ok, src


def pm3_cmd_segment(out, cmd):
    """Output emitted AFTER `cmd`'s echo line, up to the next prompt. "" if not found.

    ⚠ THE ECHO MUST BE EXCLUDED, and this is not paranoia: the verify match is case-insensitive,
    so the expect string "Indala" matches the echoed command `lf indala reader` no matter what the
    tag holds. An earlier verify failed exactly this way -- it matched the echoed command and so
    could not fail. Start after the echo's newline, stop at the next prompt so one command's output
    cannot be read as another's.
    """
    if not cmd:
        return ""
    i = out.find(cmd)
    while i != -1:
        nl = out.find("\n", i)
        if nl != -1:
            rest = out[nl + 1:]
            j = rest.find("pm3 --> ")
            seg = rest if j == -1 else rest[:j]
            if seg.strip():
                return seg
        i = out.find(cmd, i + 1)
    return ""


def pm3_verified_from_out(out, expect):
    """Did the Proxmark confirm `expect`? Two witnesses accepted: `lf search`, or the protocol's
    own reader (found via the clone's own Hint line). Works on STORED output.

    ⚠ THE LIVE RUN AND A RESCORE MUST NOT REACH DIFFERENT VERDICTS ON THE SAME BYTES. That is
    precisely how idteck came out WRONG_ID live and READ on rescore, so pm3_program_and_verify
    and rescore both call this rather than each testing the output their own way.
    """
    want = (expect or "").lower()
    if not want:
        return False
    hint = re.search(r"Hint: Try `([^`]+)`", out or "")
    seg_search = pm3_search_segment(out or "")
    seg_reader = pm3_cmd_segment(out or "", hint.group(1) if hint else None)
    return ((bool(seg_search) and want in seg_search.lower())
            or (bool(seg_reader) and want in seg_reader.lower()))


def blocks_match(spec, out):
    """Did the tag read back exactly the blocks `spec` asked for? -> (ok, mismatches).

    ⚠ ONE RULE, SHARED BY THE LIVE WRITE AND RESCORE. A T55XX row is verified by reading its blocks
    back, not by demodulating anything, so the demod-based verify would score every one of them
    INCONCLUSIVE on the next --rescore -- silently invalidating rows that had passed. That live-vs-
    rescore split already produced one false WRONG_ID today; it is not getting a second chance.
    """
    want = [b.strip().upper() for b in spec.split(",") if b.strip()]
    got = camp.parse_dump_blocks(out or "")
    bad = [(i, want[i], got.get(i)) for i in range(len(want)) if got.get(i) != want[i]]
    return (not bad and bool(want)), bad


def pm3_verified_from_record(pm3_out, pm3_clone, expect):
    """Verification verdict for ANY row type, from stored output. -> bool."""
    c = str(pm3_clone or "")
    if c.startswith(T55XX_PREFIX):
        return blocks_match(c[len(T55XX_PREFIX):], pm3_out)[0]
    return pm3_verified_from_out(pm3_out, expect)


def pm3_write_blocks(pm3_bin, spec):
    """Write explicit T55xx blocks, verify by reading them back. -> (out, ok, None).

    ⭐ THIS IS THE ANSWER TO "why not just write it with the Proxmark". You can -- once you know the
    block values. The reason the three odd protocols needed the Flipper at all is that nobody wrote
    their ENCODER for the Proxmark client, so there was nothing to compute the blocks FROM. Deriving
    them myself would have made my own reimplementation the authority, and a mistake there would look
    exactly like a firmware fault. But that is a one-time problem: let the Flipper write the tag ONCE,
    read the blocks off it with `lf t55xx dump`, and from then on the Proxmark can reproduce that tag
    exactly, with no GUI step, on every build and every fork.
    ⚠ ASCENDING FROM BLOCK 0, because that is what the Proxmark's own clone_t55xx_tag does: config
    block first, then data. Do not invent an order.
    ⭐ AND THE VERIFICATION IS STRONGER THAN A DEMOD. We wrote known values, so reading them back is a
    direct, protocol-independent check -- no encoder, no demodulator, nothing to misinterpret. It also
    makes BLOCKS_MISMATCH redundant for these rows: the block values live in the clone string itself,
    so two arms that wrote different bits already differ as CLONE_MISMATCH.
    """
    blocks = [b.strip().upper() for b in spec.split(",") if b.strip()]
    cmds = [f"lf t55xx write -b {i} -d {b} --verify" for i, b in enumerate(blocks)]
    out = camp.pm3_exec(pm3_bin, cmds + ["lf t55xx detect", "lf t55xx dump"], False, timeout=200)
    if "Communicating with PM3" not in out:
        print("    ⛔ THE PROXMARK CLIENT NEVER CONNECTED -- nothing was written. NOT a tag fault."
              " Close any other `pm3` session and re-run with --resume.")
        return out, None, None
    ok, bad = blocks_match(spec, out)
    if bad:
        print("    ⚠ BLOCK READBACK MISMATCH -- the tag does not hold what we wrote:")
        for i, w, g in bad:
            print(f"        block {i}: wrote {w}, read back {g or '(missing)'}")
    return out, ok, None


def pm3_program_and_verify(pm3_bin, pm3_clone, pm3_expect):
    """Clone, then verify with `lf search` AND the protocol's own reader. -> (out, ok, verify_cmd).

    ⚠⚠ THIS EXISTED TWICE AND ONLY ONE COPY GOT THE FIX. The hint-derived reader command was added
    to the --positions sweep path while the MAIN LOOP still ran a bare `lf search`, so the fix was
    unreachable from a normal run. Accepting the protocol's own reader as a second witness is still
    right -- it is the command the Proxmark itself nominates -- but do NOT credit it with fixing
    gproxii: that was a bad --xor value in our own clone command, and `lf search` reads a correctly
    written G-Prox-II tag perfectly well. See the SUBSET note on gproxii.
    ⚠ AND THE SWEEP COPY VERIFIED AGAINST THE SEARCH SEGMENT ONLY, so it fetched the reader output
    and then ignored it -- a fix that was present but inert. Accept EITHER witness.
    """
    # explicit block recipes skip the clone/demod dance entirely -- see pm3_write_blocks
    if pm3_clone.startswith(T55XX_PREFIX):
        return pm3_write_blocks(pm3_bin, pm3_clone[len(T55XX_PREFIX):])
    first = camp.pm3_exec(pm3_bin, [pm3_clone], False, timeout=90)
    # ⚠ AN UNREACHABLE PROXMARK IS NOT A BENCH FAULT AND MUST NOT BE SCORED AS ONE. If another
    # pm3 session already holds the port, the client never connects -- and the run then blames the
    # tag for something that is purely an open terminal. Diagnose it by the ABSENCE of the
    # connection banner rather than by matching an OS-specific errno string.
    if "Communicating with PM3" not in first:
        print("    ⛔ THE PROXMARK CLIENT NEVER CONNECTED. This is NOT a bench fault and NOT a")
        print("    ⛔ firmware finding -- nothing was written or read. The usual cause is another")
        print("    ⛔ `pm3` session holding the port: close it and re-run with --resume.")
        return first, None, None
    if "Hint: Try" not in first and "-------------- Low Frequency" in first:
        print("    ⚠ THE PROXMARK DID NOT RECOGNISE THAT COMMAND -- it printed its `lf` help."
              " Check the subcommand NAME (the command table is authoritative, the source"
              " filename is not: it is `lf gproxii`, not `lf guard`).")
    hint = re.search(r"Hint: Try `([^`]+)`", first)
    verify = hint.group(1) if hint else None
    proto_word = pm3_clone.split()[1] if pm3_clone.startswith("lf ") else None
    if not verify and proto_word:
        verify = f"lf {proto_word} reader"
    out = first + "\n" + camp.pm3_exec(
        pm3_bin, ["lf search"] + ([verify] if verify else []), False, timeout=150)
    return out, pm3_verified_from_out(out, pm3_expect), verify


def read_attempts(port, n, deadline, reconnect, stop_after=0):
    """Read the tag n times. -> (attempts, port), port replaced if a reconnect was needed.

    ⚠⚠ ONE IMPLEMENTATION, kept as a function rather than inlined back. Every other piece of duplicated logic in this suite has drifted and produced a
    wrong verdict -- four of them in one session, including a false WRONG_ID. Copying it would have
    been the fifth.
    ⚠ REPEAT, BEST-OF-N. One attempt is not a measurement at marginal coupling: a refusal is a
    property of the PLACEMENT, and ~50% rates are normal at marginal gap (block 0 read 32/70 at one
    untouched placement). A one-shot suite reports coupling noise as a cross-build regression.
    ⚠ gap between invocations: back-to-back CLI calls intermittently fragment the heap until the
    97KB cli_rfid.fal cannot load (STATUS #20). Cheap insurance, not superstition.
    """
    # ⚠ SHOW PROGRESS PER ATTEMPT. A full miss costs n x (deadline + 1s) -- 10 attempts at the 25s
    # default is ~4.5 MINUTES of total silence, which is indistinguishable from a hang. The operator
    # twice suspected a freeze and once killed a healthy run because of it. The --positions path
    # already printed [RRRR....] and the main loop printed nothing; both now come through here.
    attempts = []
    if n:
        sys.stdout.write("    [")
        sys.stdout.flush()
    for _ in range(n):
        time.sleep(1.0)
        try:
            nm, dt, rw = rfid_read(port, deadline)
            attempts.append(dict(name=nm, data=dt, raw=rw, status="READ" if nm else "NO_READ"))
            sys.stdout.write("R" if nm else ".")
            sys.stdout.flush()
            # ⭐ STOP EARLY ONCE THE ANSWER IS IN, and only ever on SUCCESSES. The attempt count
            # exists to stop a marginal reader being called a NO_READ -- keri reads ~1/3 on both
            # builds, so 0/3 would happen by chance about a third of the time. That argument applies
            # only when reads are MISSING. Once several attempts have agreed, further ones add
            # nothing but wall clock, and the cost is real: a miss burns the whole deadline.
            # ⚠ This can never manufacture a NO_READ or hide an INCONSISTENT: it triggers only after
            # `stop_after` reads that AGREE, and a disagreement keeps the loop running to the end.
            if stop_after:
                good = [x for x in attempts if x["status"] == "READ"]
                if len(good) >= stop_after and len({(x["name"], x["data"]) for x in good}) == 1:
                    sys.stdout.write(f" (stopped early: {len(good)} agreeing reads)")
                    break
        except Exception as e:
            # ⚠ A DISCONNECT IS NOT A RESULT. Reconnect and score INCONCLUSIVE; scoring it as a
            # failed read would turn a cable wobble into a reported firmware regression.
            attempts.append(dict(name=None, data=None, raw=f"{type(e).__name__}: {e}",
                                 status="INCONCLUSIVE"))
            sys.stdout.write("?")
            sys.stdout.flush()
            print(f"\n    INCONCLUSIVE  transport fault: {e}")
            try:
                port.close()
            except Exception:
                pass
            port = reconnect()
    if n:
        sys.stdout.write("]\n")
        sys.stdout.flush()
    return attempts, port


def summarise_attempts(attempts, pm3_ok, allow_any=None):
    """-> (hits, name, data, raw, distinct, status).

    ⚠ DISAGREEMENT BETWEEN ATTEMPTS IS ITS OWN FINDING. A miss is noise, but the same tag decoding
    two DIFFERENT ways is a real defect and must never be hidden by best-of-N -- hence INCONSISTENT
    outranking READ here.
    """
    hits = [x for x in attempts if x["status"] == "READ"]
    distinct = {(x["name"], x["data"]) for x in hits}
    name = hits[0]["name"] if hits else None
    data = hits[0]["data"] if hits else None
    raw = "\n---attempt---\n".join(x["raw"] for x in attempts)
    if pm3_ok is False:
        status = "INCONCLUSIVE"
    elif len(distinct) > 1:
        # ⚠ SCOPED, NOT BLUNTED. Only values the ROW declared valid are excused; anything else is
        # still INCONSISTENT. A tag holding two EM4100 frames has two correct answers, and calling
        # that a defect would report the test's own assumption as a firmware fault -- but silencing
        # the detector generally would throw away the one check that catches a real misdecode.
        ok_set = {v.upper() for v in (allow_any or [])}
        if ok_set and all((d or "").upper() in ok_set for _, d in distinct):
            status = "READ"
        else:
            status = "INCONSISTENT"
    elif hits:
        status = "READ"
    elif any(x["status"] == "INCONCLUSIVE" for x in attempts):
        status = "INCONCLUSIVE"
    else:
        status = "NO_READ"
    return hits, name, data, raw, distinct, status


def rendered_fields(raw):
    """Flipper-rendered fields, with the SAME alias map applied so PM3 'Card' meets Flipper 'CIN'.
    Without this the two dicts share no keys and the identity check silently passes everything."""
    out = {}
    for k, v in RENDER_RE.findall(raw):
        k = k.strip()
        if k in ("Reading",):
            continue
        out[_ALIAS.get(k.lower(), k)] = v
    return out


def rfid_read(port, deadline_s=25.0, mode=None):
    """-> (protocol_name, hexdata, raw_text) or (None, None, raw_text) for NO_READ."""
    cmd = "rfid read" + (f" {mode}" if mode else "")
    port.reset()
    port.write((cmd + "\r").encode())
    buf = bytearray()
    t0 = time.time()
    got = None
    while time.time() - t0 < deadline_s:
        chunk = port.read()
        if chunk:
            buf += chunk
            tail = bytes(buf).decode("utf-8", "replace")
            m = RESULT_RE.search(tail.replace(cmd, "", 1))
            if m and "Reading RFID" in tail:
                got = m
                break
        else:
            time.sleep(0.05)
    # Abort only when we did NOT get a result. On success the CLI's loop has already broken on
    # LFRFIDWorkerReadDone and returned to the prompt, so a Ctrl+C then just echoes a stray ^C into the
    # transcript. On a timeout the worker IS still running and the abort is mandatory.
    if not got:
        port.write(b"\x03")
    t1 = time.time()
    while time.time() - t1 < 6.0:
        chunk = port.read()
        if chunk:
            buf += chunk
            if "Reading stopped" in bytes(buf[-400:]).decode("utf-8", "replace"):
                break
        else:
            time.sleep(0.05)
    raw = bytes(buf).decode("utf-8", "replace")
    if got:
        return got.group(1).strip(), got.group(2).strip(), raw
    m = RESULT_RE.search(raw.replace(cmd, "", 1))
    if m:
        return m.group(1).strip(), m.group(2).strip(), raw
    return None, None, raw


# ⭐ A CONTINUOUS COUPLING PROBE, so a position sweep yields something predictable rather than six
# binary outcomes. `rfid t5577 raw <blk> <ms>` is READ-ONLY (t5577_read_reply_capture, no writes -- unlike
# `durstats`, which writes block 0 and 1 and would destroy the configuration mid-sweep) and prints
# "Captured N edges" followed by every level:duration pair. From that:
#   edges     -- is the tag energised and answering at all, and how much is coming back
#   modal_us  -- the dominant rising-to-rising period, which says whether the reply is structured
#   in_band   -- share of periods near the expected bit/half-bit, i.e. how clean that structure is
# Binary read/no-read across six positions tells the operator almost nothing about WHY; these numbers
# vary continuously with coupling and are what a physical trend would show up in.


def device_protocols(port):
    """Protocol names this FIRMWARE implements, asked of the device itself. -> set or None.

    ⭐ ASK THE DEVICE, DO NOT MAINTAIN A LIST PER FORK. The protocol sets are nested but not equal --
    OFW has 24, Unleashed 25, Momentum 26 -- so running the full matrix on OFW would report Indala224
    and InstaFob as NO_READ or PROTOCOL MISMATCH: two false faults, in someone else's tree, for
    protocols that simply are not there. A hardcoded per-fork exclusion list would work until the day
    it silently went stale against a fork that added one.
    The Flipper answers this itself: any unknown protocol name makes `rfid emulate` print
    "Available protocols:" followed by every name it has (lfrfid_cli.c). Emulate is non-destructive
    with a bad name -- it fails argument parsing before touching the radio.
    ⚠ Returns None if the listing cannot be parsed, and the caller then runs everything rather than
    silently skipping the whole matrix. A filter that fails closed would report "PASS: 0 protocols".
    """
    out = camp.run_cmd(port, "rfid emulate __NOSUCHPROTO__ 00", 25, fault_cue=False)
    txt = out if isinstance(out, str) else out[0]
    if "Available protocols" not in txt:
        return None
    names = re.findall(r"^\s+(.+?),\s*\d+ bytes long\s*$", txt, re.M)
    return set(names) or None


def verify_commit(port, expect, allow_dirty=None):
    # ⚠⚠ A SILENT CLI IS NOT A WRONG BUILD, AND MUST NOT BE REPORTED AS ONE. If the Flipper is sitting
    # in the LF RFID app it holds the LF worker and its CLI thread stops executing commands -- yet a
    # fresh USB-CDC session still prints its connect BANNER, so the port looks perfectly healthy.
    # device_info then times out with no output, `got` falls back to "?", and the old code exited with
    # "device is on ?, expected <sha>" -- which reads as a flashing problem and sends you looking in
    # entirely the wrong place. It is an operator-recoverable state: exit the app, or reboot, and go on.
    # ⚠ WAIT BEFORE BLAMING ANYONE. A just-flashed Flipper reboots through its updater and its CLI is
    # legitimately absent for the better part of a minute -- and this went straight to "the LF RFID app
    # is open", which is the wrong first guess immediately after a flash and cost a confusing FATAL on a
    # device that was simply still booting. Retry silently first; only then involve the operator.
    txt = ""
    for _ in range(12):
        out = camp.run_cmd(port, "device_info", 20, fault_cue=False)
        txt = out if isinstance(out, str) else out[0]
        if "firmware_commit" in txt:
            break
        time.sleep(5)
    for attempt in range(4):
        if "firmware_commit" in txt:
            break
        out = camp.run_cmd(port, "device_info", 25, fault_cue=False)
        txt = out if isinstance(out, str) else out[0]
        if "firmware_commit" in txt:
            break
        print("\n  ⛔ THE FLIPPER CLI IS NOT EXECUTING COMMANDS. The port is open and the connect")
        print("  ⛔ banner arrives, but device_info returned nothing -- which is what happens while")
        print("  ⛔ the LF RFID app is open, because it holds the LF worker for its whole lifetime.")
        print("  ⛔ This is NOT a bad flash and NOT a tag fault; nothing has been measured.")
        if attempt == 3:
            sys.exit("FATAL: the Flipper CLI never responded. Reboot it and re-run with --resume.")
        camp.ask("  >>> EXIT the app back to the Flipper desktop (or reboot it), then press Enter: ")
    m = re.search(r"firmware_commit\s*:\s*([0-9a-f]+)", txt)
    dirty = re.search(r"firmware_commit_dirty\s*:\s*(\w+)", txt)
    got = m.group(1) if m else "?"
    if not expect:
        print(f"  device is on {got} (dirty={dirty.group(1) if dirty else '?'})")
        return got
    if not got.startswith(expect[:8]):
        sys.exit(f"FATAL: device is on {got}, expected {expect}. Refusing to test an unknown build.")
    if dirty and dirty.group(1) != "false":
        # ⚠⚠ THE DIRTY GUARD STAYS, but it is overridable WITH A RECORDED REASON. It exists because a
        # silently-failed flash once cost eight hours, and that is about not testing an UNKNOWN build --
        # not about refusing a build whose deviation has been identified and shown irrelevant.
        # The case that forced this: Unleashed's resource bundle would not build until a stale vendored
        # SubGHz app was fixed (-Werror=format=, a FuriString* in a %s), which makes the TREE dirty. That
        # app is apptype=MENUEXTERNAL, i.e. a separate .fap, and `nm firmware.elf` finds ZERO
        # subghz_remote symbols against 24 furi_hal_rfid and 21 protocol_em4100 -- so the firmware under
        # test is unaffected, measured with a positive control rather than argued from the manifest.
        # ⚠ The reason is written into EVERY record. A dirty build accepted without a trace in the
        # artefact is exactly the unknown build the guard was written to stop.
        if not allow_dirty:
            sys.exit("FATAL: firmware_commit_dirty is true. Refusing to test a dirty build."
                     " If the deviation is known and irrelevant, pass --allow-dirty 'reason'.")
        print(f"  ⚠⚠ DIRTY BUILD ACCEPTED. Reason recorded in every record: {allow_dirty}")
        return got
    print(f"  firmware verified: {got}, not dirty")
    return got


def rescore(path):
    """Recompute verdicts from the STORED raw output. Every record keeps the full PM3 and Flipper text,
    so a harness bug found later can be corrected without re-running the hardware -- which matters when
    the hardware costs an operator moving a tag 16 times. Three of this suite's own bugs (a phantom
    ID='f', a verify that matched the echoed command, a PM3/Flipper field-name mismatch) were fixed after
    a full baseline run, and this recovered 6 of the 8 protocols instead of redoing them."""
    recs = json.load(open(path))
    bylabel = {row[0]: row for row in SUBSET}
    for r in recs:
        # ⚠ RE-DERIVE THE VERIFY, not just the identity. The first rescore only asked whether `lf search`
        # ran, so viking -- whose clone was REJECTED and whose search found the previous protocol -- still
        # scored READ. Records written before pm3_expect was stored fall back to the matrix.
        exp = r.get("pm3_expect") or (bylabel.get(r["label"], (None,) * 4)[3])
        r["pm3_expect"] = exp
        r["pm3_verified"] = pm3_verified_from_record(
            r.get("pm3_out", ""), r.get("pm3_clone", ""), exp)
        r["pm3_id"] = pm3_identity(r.get("pm3_out", ""), exp)
        # ⚠ THE FIRST ATTEMPT IS NOT NECESSARILY THE SUCCESSFUL ONE. indala26 read 2/3 with the miss
        # first, so taking segment[0] found no fields and silently dropped the identity check to None --
        # a check that quietly stops checking is the worst outcome available. Pick the segment that
        # actually carries the decode.
        segs = (r.get("raw") or "").split("---attempt---")
        first = next((g for g in segs if r.get("got_name") and r["got_name"] in g), segs[0])
        flds = rendered_fields(first) if r.get("got_name") else {}
        r["fields"] = flds
        # ⚠ TAKE want FROM THE TABLE, NOT FROM THE RECORD. A pinned expectation IS scoring logic, and
        # rescore exists to apply current scoring to stored raw data -- but this read the `want` frozen
        # into the record at capture time, so pinning electra/insta_fob/hid_ex_generic changed nothing
        # and all three stayed NAME-ONLY through a rescore that was supposed to upgrade them. Same shape
        # as the pm3_expect fallback two lines up. Record value remains the fallback for labels no
        # longer in the matrix, so old artefacts stay readable.
        want = (bylabel.get(r["label"], (None,) * 5)[4] if r["label"] in bylabel
                else None) or r.get("want") or {}
        id_ok, src = score_identity(r.get("pm3_clone", ""), r.get("got_name"),
                                    r.get("got_data"), flds, r["pm3_id"], want)
        # ⚠ PERSIST THE TABLE'S want, do not just read it. Records captured before a declaration
        # existed keep the old one, and downstream tools that read r["want"] then see two different
        # shapes for the same row: em4100_multi's base arm reported a first-hit tuple while its fixed
        # arm reported the any_of token, and the comparison called that a REGRESSION. Rescore exists
        # to bring stored records up to the current matrix; leaving a field stale defeats that.
        r["want"] = want
        r["id_ok"], r["id_src"], r["id_checked"] = id_ok, src, id_ok is not None
        # ⚠ STAMP THE REVISION THAT SCORED IT. Without this a rescored record claims the rev it was
        # CAPTURED under while carrying verdicts computed by newer logic -- which defeats the whole
        # purpose of having a revision stamp. Capture rev is kept separately so provenance is not lost.
        if r.get("suite_rev") != SUITE_REV:
            r.setdefault("captured_rev", r.get("suite_rev"))
            r["suite_rev"] = SUITE_REV
        if not r["pm3_verified"]:
            r["status"] = "INCONCLUSIVE"
            r["note"] = ("PM3 did not confirm %r -- neither `lf search` nor the protocol's own"
                         " reader -- BENCH FAULT, re-run" % exp)
        elif r["status"] == "INCONSISTENT":
            # ⚠ RE-EVALUATE INCONSISTENT ON RESCORE. A row that declares several valid answers can
            # have been captured before that declaration existed -- em4100_multi was -- and a status
            # a rescore refuses to revisit is a verdict frozen at its most alarming reading.
            allow = {v.upper() for v in ((bylabel.get(r["label"], (None,) * 5)[4] or {}).get("any_of") or [])}
            seen = {(d or "").split(" ", 1)[-1].upper() for d in (r.get("distinct") or [])}
            if allow and seen and seen <= allow:
                r["status"] = "READ"
                r["note"] = "several DECLARED-valid decodes (%s) -- not a disagreement" % ", ".join(sorted(seen))
        elif r["status"] in ("READ", "WRONG_ID"):
            r["status"] = "WRONG_ID" if id_ok is False else "READ"
    # de-duplicate by label, keeping the LAST occurrence -- the newest run supersedes
    seen, dedup = {}, []
    for r in recs:
        seen[r["label"]] = r
    for lab in dict.fromkeys(r["label"] for r in recs):
        dedup.append(seen[lab])
    dropped = len(recs) - len(dedup)
    recs = dedup
    json.dump(recs, open(path, "w"), indent=1)
    print(f"  rescored {len(recs)} record(s) in {path}"
          + (f" (dropped {dropped} superseded duplicate(s))" if dropped else ""))
    for r in recs:
        print(f"    {r['label']:14s} {r['status']:12s} {r.get('got_name')!r:12s} "
              f"{r.get('got_data')!r:22s} id={r.get('id_ok')} via {r.get('id_src') or '-'}"
              f"{'  ' + r['note'] if r.get('note') else ''}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect-commit", default=None)
    ap.add_argument("--build", help="label for this build, e.g. 'momentum+halfix'")
    ap.add_argument("--only", default=None, help="run one protocol by label or expected name")
    ap.add_argument("--out", default=None)
    ap.add_argument("--deadline", type=float, default=25.0)
    ap.add_argument("--allow-dirty", metavar="REASON",
                    help="accept a firmware_commit_dirty build, recording REASON in every record."
                         " Only for a deviation you have IDENTIFIED and shown irrelevant to the LF"
                         " path -- the guard exists to stop unknown builds, not known ones.")
    ap.add_argument("--stop-after", type=int, default=3,
                    help="stop a protocol early after this many AGREEING reads (0 disables). Cuts"
                         " wall clock on reliable rows without weakening a NO_READ, which is only"
                         " ever declared after the full attempt count.")
    ap.add_argument("--attempts", type=int, default=3,
                    help="reads per protocol; 1 is not enough at marginal coupling")
    ap.add_argument("--no-prompt", action="store_true", help="do not wait for tag placement (debug)")
    ap.add_argument("--silicon", default="unknown", help="run-level label, e.g. sc-copper / inv-dual")
    # ⚠ POSITION IS A FIRST-CLASS VARIABLE AND MUST BE RECORDED. Learned the hard way: EM4100/16 needs a
    # LARGER air gap than every other protocol (0/2 at 3-6mm, 10/10 at 9mm), so a result without its gap
    # is not reproducible and cannot be compared. The four completed matrix runs predate this and carry
    # no position at all, which is precisely why they are being repeated rather than annotated after the
    # fact -- writing in a number we never recorded would be inventing data.
    # ⭐ --position auto: record EACH protocol's own measured window as its position. The two awkward
    # protocols have DISJOINT windows (indala26 0/5 at 8mm; em4100_16 0/5 at 7mm), so no single gap covers
    # the matrix -- but the prompt already names the right gap per protocol, so one run can still cover all
    # eight provided each record carries the gap it was actually taken at. Beats two runs per build, and
    # beats a run-level position that would be a lie for at least one row.
    ap.add_argument("--position", default="unrecorded",
                    help="air gap label for the run, or 'auto' to record each protocol's own window")
    ap.add_argument("--pm3", action="store_true", help="drive the Proxmark: program + verify per protocol")
    ap.add_argument("--pm3-bin", default="pm3")
    # ⚠ ONE TAG means the cycle is inherently per-protocol: you cannot pre-program eight protocols onto
    # one tag. So the phases split PER PROTOCOL -- `--phase pm3 --only X`, move the tag, `--phase flipper
    # --only X`. Each invocation is then non-interactive, which is what lets an operator move hardware
    # between two commands instead of answering prompts inside one.
    ap.add_argument("--phase", choices=("both", "pm3", "flipper"), default="both")
    ap.add_argument("--resume", action="store_true",
                    help="skip protocols already recorded in --out (survives an interrupted run)")
    ap.add_argument("--state", default="/tmp/lf_suite_state.json",
                    help="carries the PM3 verdict from --phase pm3 to --phase flipper")
    # ⭐ POSITION SWEEP. For ONE fixed tag configuration, the PM3 round trip per sample is waste: the tag
    # is not being reprogrammed, so program+verify ONCE and then only reposition. Turns two tag moves per
    # sample into one, which is what makes a 6-position x 2-silicon map affordable.
    # ⚠ A 2-run sample is a LOCATOR, NOT A RATE. Any read proves the position can work; 0/2 proves
    # nothing about whether it can. Positions that read at all get a 10-run characterisation afterwards --
    # treating a 2/2 as "works here" would repeat, at smaller scale, the error that a 3/3 already caused
    # on this very protocol.
    ap.add_argument("--positions", default=None,
                    help="comma-separated position labels; sweeps them with one PM3 program up front")
    ap.add_argument("--rescore", metavar="FILE",
                    help="recompute verdicts from stored raw output; no hardware needed")
    a = ap.parse_args()

    # ⚠ --rescore MUST NOT REQUIRE --build. Rescoring reads verdicts back out of a stored file and
    # never touches hardware, but argparse's required=True rejected it outright -- which meant a
    # "rescore" that silently never ran and a diff that reported 0 changes because nothing happened.
    # A check that cannot run looks exactly like a check that passed.
    if a.rescore:
        rescore(a.rescore)
        return

    if not a.build:
        sys.exit("--build is required for a bench run (it labels the firmware under test).")

    out = a.out or f"lf_suite_{a.build.replace('/', '_')}.json"
    recs = []

    def flush():
        """⚠ WRITE AFTER EVERY PROTOCOL. Writing once at the end -- inside a `finally` that a
        SerialException blows straight past -- lost an entire run to a transient USB disconnect while
        debugging this file. On a 22-protocol suite that is an hour of tag handling gone to a cable
        wobble."""
        with open(out, "w") as f:
            json.dump(recs, f, indent=1)

    def connect():
        import glob
        for _ in range(40):
            ports = sorted(glob.glob("/dev/cu.usbmodemflip*"))
            if ports:
                try:
                    p_, _b = camp.open_port(ports[0])
                    return p_
                except Exception:
                    pass
            time.sleep(3)
        sys.exit("no Flipper port found (waited 120s)")

    port = connect()
    try:
        # ⚠ RECORD THE COMMIT, do not merely check it. The suite verified the firmware and then
        # threw the answer away, so a results file said only 'baseline-nofix' -- a label I chose,
        # not evidence. Provenance has to survive in the artefact for a reviewer to trust the pair.
        fw_commit = verify_commit(port, a.expect_commit, a.allow_dirty)
        # ⚠ --only TAKES A LIST. A targeted run is the normal case for a third fork -- Unleashed needs
        # six specific rows, not one and not all 26 -- and one protocol per invocation means six
        # commands, six firmware checks and six chances to fumble one. Accept commas.
        want_only = [x.strip() for x in (a.only or "").split(",") if x.strip()]
        rows = [r for r in SUBSET if not want_only or r[0] in want_only or r[1] in want_only]
        if want_only:
            missing = [x for x in want_only if not any(x in (r[0], r[1]) for r in SUBSET)]
            if missing:
                sys.exit(f"--only names protocols not in the matrix: {', '.join(missing)}")
        if not rows:
            sys.exit(f"--only {a.only!r} matched nothing")
        if a.resume and os.path.exists(out):
            try:
                prev = json.load(open(out))
                done = {r["label"] for r in prev if r.get("status") in ("READ", "WRONG_ID")}
                todo = {r[0] for r in rows if r[0] not in done}
                # ⚠ REPLACE, DO NOT ACCUMULATE. The first version extended `recs` with the whole previous
                # file and then appended the new record, so a re-run left BOTH -- 10 records for 8
                # protocols, em4100_16 listed twice, and viking still in the "not scored" list after it
                # had passed. A results file that keeps stale rows alongside fresh ones is a file nobody
                # can read a verdict from.
                recs.extend([r for r in prev if r["label"] not in todo])
                rows = [r for r in rows if r[0] not in done]
                print(f"  resuming: {len(done)} already recorded, {len(rows)} to go"
                      + (f", superseding {len(prev) - len(recs)} stale record(s)"
                         if len(prev) != len(recs) else ""))
            except Exception as e:
                print(f"  (could not resume from {out}: {e})")
        # ⚠ SKIP WHAT THIS FIRMWARE DOES NOT IMPLEMENT, and say so out loud. Absent is not failed.
        have = device_protocols(port)
        if have:
            absent = [r for r in rows if r[1] not in have]
            if absent:
                rows = [r for r in rows if r[1] in have]
                print(f"\n  ⓘ {len(absent)} protocol(s) NOT IMPLEMENTED on this firmware -- skipped,"
                      f" NOT failed: {', '.join(r[0] for r in absent)}")
                print(f"  ⓘ (device reports {len(have)} protocols; the matrix defines {len(SUBSET)})")
        else:
            print("\n  ⚠ could not read the device's protocol list -- running the whole matrix."
                  " A row this firmware lacks will look like a fault; check before believing one.")
        print(f"\n  {len(rows)} protocol(s) on silicon {a.silicon!r}, position {a.position!r},"
              f" build {a.build!r}, {a.attempts} attempt(s) each")
        if a.position == "unrecorded" and not a.positions:
            print("  ⚠ NO --position GIVEN. The air gap is load-bearing (EM4100/16 needs ~9mm where")
            print("  ⚠ others want 3-6mm), so a run without it cannot be reproduced or compared.")
        print("  ⛔ NOT the orange fobs -- blocks 3-6 do not work on that silicon (see the matrix note)")
        # ⚠ DEFINED BEFORE THE FIRST USE, not just somewhere in the function. This sat below the
        # --positions branch that now calls it: py_compile passes on that happily and it would have
        # raised NameError on the first transport hiccup mid-sweep, which is the worst possible moment.
        # Compiling is not running.
        def reconnect():
            p = connect()
            verify_commit(p, a.expect_commit, a.allow_dirty)
            return p

        if a.positions:
            if len(rows) != 1:
                sys.exit("--positions needs exactly one protocol (use --only)")
            label, expect_name, pm3_clone, pm3_expect, want, gap = rows[0]
            pm3_out, pm3_ok = "", None
            if a.pm3:
                camp.ask(f"\n>>> [PM3] program {label} ONCE, then press Enter: ")
                # ⭐ THE PROXMARK TELLS US THE VERIFY COMMAND. Every successful clone ends with
                #   [?] Hint: Try `lf pyramid reader` to verify
                # so run the clone first, read the hint, and use it -- authority over convention (§7.43).
                # Deriving it from the clone string worked only while the clone string was right.
                # ⚠ AND THE ABSENCE OF A HINT IS A DIAGNOSIS. An unrecognised subcommand makes the PM3
                # print its `lf` help instead, with no hint at all -- which is precisely what `lf guard
                # clone` did for three runs while I guessed at the arguments. Detect it and SAY so.
                pm3_out, pm3_ok, _v = pm3_program_and_verify(a.pm3_bin, pm3_clone, pm3_expect)
                print(f"    PM3 program+verify: {'OK' if pm3_ok else 'FAILED'}")
                if not pm3_ok:
                    cue_fault("bench fault, the Proxmark could not verify the tag")
                    sys.exit("refusing to sweep positions with an unverified tag")
            pm3_id = pm3_identity(pm3_out, pm3_expect)
            for pos in [x.strip() for x in a.positions.split(",") if x.strip()]:
                camp.ask(f"\n>>> [Flipper] move the tag to position '{pos}', then press Enter: ")
                # ⚠⚠ THE FIFTH TIME. This loop was a COPY of read_attempts, which is the function I
                # extracted expressly so a second copy could not exist -- and the copy was already
                # here, in the sweep path, unmigrated. So --stop-after and the per-attempt progress
                # output both silently did nothing here: the operator watched a sweep run all ten
                # attempts on a position that had already read three times, with no live output, and
                # reasonably asked whether they were on the wrong branch. Extracting a function does
                # not help if the existing duplicate is left where it is.
                atts, port = read_attempts(port, max(1, a.attempts), a.deadline, reconnect,
                                           stop_after=a.stop_after)
                h, _n, _d, _raw, _distinct, st = summarise_attempts(atts, None)
                seq = "".join("R" if x["status"] == "READ" else
                              ("?" if x["status"] == "INCONCLUSIVE" else ".") for x in atts)
                recs.append(dict(build=a.build, firmware_commit=fw_commit, dirty_reason=a.allow_dirty, label=label, silicon=a.silicon, position=pos,
                                 expect=expect_name, got_name=h[0]["name"] if h else None,
                                 got_data=h[0]["data"] if h else None, status=st,
                                 n_attempts=len(atts), n_read=len(h), suite_rev=SUITE_REV,
                                 attempts_cfg=a.attempts, pm3_expect=pm3_expect, pm3_verified=pm3_ok,
                                 pm3_id=pm3_id, want=want, name_matches=(h and h[0]["name"] == expect_name),
                                 seq=seq,
                                 raw="\n---attempt---\n".join(x["raw"] for x in atts)))
                flush()
                print(f"    {pos:14s} [{seq}] {st:12s} {len(h)}/{len(atts)}"
                      f"  {h[0]['name'] if h else ''} {h[0]['data'] if h else ''}")
            # ⛔ THE COUPLING PROBE IS GONE, NOT FIXED (2026-08-22). It reported edges=0/1 and
            # modal=None on every position of every sweep -- it was not measuring anything -- while
            # printing three numeric columns that read exactly like measurements. It fed no verdict, so
            # nothing depended on it, and every position finding in this project came from READ COUNTS
            # instead, which is the more direct instrument. A broken diagnostic that prints plausible
            # numbers is worse than no diagnostic: this project has lost hours to plausible zeros.
            # If coupling ever needs measuring again, write it fresh with a positive control.
            print("\n  POSITION MAP   (read counts; the coupling probe was removed -- see comment)")
            print(f"    {'position':14s} {'seq':8s} reads")
            for r in recs:
                print(f"    {r.get('position',''):14s} [{r.get('seq',''):6s}] "
                      f"{r['n_read']}/{r['n_attempts']}")
            hits = [r for r in recs if r["n_read"]]
            if hits:
                print(f"\n  ⇒ {len(hits)} position(s) produced a read. NEXT: characterise the best with"
                      f" --attempts 10 before drawing any conclusion -- a 2-run sample locates, it does"
                      f" not measure.")
            else:
                print("\n  ⇒ NO position produced a read. That is evidence this configuration is not"
                      " readable on this rig, not evidence about any firmware change.")
            return

        last_gap = None
        for label, expect_name, pm3_clone, pm3_expect, want, gap in rows:
            pm3_out, pm3_ok = "", None
            if a.phase == "flipper":
                # pick up what the pm3 phase recorded for this protocol
                try:
                    st = json.load(open(a.state))
                except Exception:
                    st = {}
                e = st.get(label)
                if e is None:
                    print(f"    ⚠ no PM3 record for {label!r} in {a.state} -- run --phase pm3 first."
                          f" Refusing to read a tag whose contents were never verified.")
                    continue
                pm3_out, pm3_ok = e.get("pm3_out", ""), e.get("pm3_ok")
                print(f"    (PM3 phase said: {'OK' if pm3_ok else 'FAILED'})")
            elif a.pm3:
                if a.phase == "both":
                    camp.ask(f"\n>>> [PM3] [{label}] move the tag to the PROXMARK,"
                             f" then press Enter: ")
                # program, then VERIFY IN PLACE. A step that programs without confirming is not a
                # control -- it is an assumption, and this suite exists because one of those cost an hour.
                pm3_out, pm3_ok, _v = pm3_program_and_verify(a.pm3_bin, pm3_clone, pm3_expect)
                if pm3_ok is None:
                    # the client never connected -- already diagnosed and printed. Not a bench fault.
                    pm3_ok = False
                # ⚠ SAY WHAT WAS ACTUALLY CHECKED. T55XX rows are verified by reading the written
                # blocks back, not by demodulating a protocol, so they have no expect string -- and
                # printing "looking for ''" invited the reader to think the check was empty when it is
                # in fact the strongest one in the suite.
                how = ("block readback" if pm3_clone.startswith(T55XX_PREFIX)
                       else f"looking for {pm3_expect!r}")
                print(f"    PM3 program+verify: {'OK' if pm3_ok else 'FAILED'} ({how})")
                if not pm3_ok:
                    print("    ⚠ the PM3 could not confirm the tag holds what we asked for. This is a"
                          " BENCH FAULT, not a firmware finding -- scoring INCONCLUSIVE and skipping.")
                    cue_fault("bench fault, skipping, the Proxmark could not verify the tag")
                    # ⚠ AND DO NOT THEN ASK FOR THE TAG. The attempts loop is already zeroed, so
                    # prompting the operator to move it buys a guaranteed no-op -- wasted handling in a
                    # run whose entire cost IS the handling.
                    recs.append(dict(build=a.build, firmware_commit=fw_commit, dirty_reason=a.allow_dirty, label=label, expect=expect_name,
                                     silicon=a.silicon, gap_window=gap, suite_rev=SUITE_REV,
                                     position=(gap if a.position == 'auto' else a.position),
                                     attempts_cfg=a.attempts, pm3_clone=pm3_clone,
                                     pm3_expect=pm3_expect, pm3_verified=False, pm3_out=pm3_out,
                                     pm3_id={}, got_name=None, got_data=None, status="INCONCLUSIVE",
                                     name_matches=False, fields={}, want=want, id_checked=False,
                                     id_ok=None, id_src="", n_attempts=0, n_read=0, distinct=[],
                                     raw="", note="PM3 could not confirm %r -- BENCH FAULT" % pm3_expect))
                    flush()
                    continue
                if a.phase == "pm3":
                    # record and stop; the operator now moves the tag and runs --phase flipper
                    try:
                        st = json.load(open(a.state))
                    except Exception:
                        st = {}
                    st[label] = dict(pm3_out=pm3_out, pm3_ok=pm3_ok, clone=pm3_clone,
                                     pm3_id=pm3_identity(pm3_out, pm3_expect),
                                     pm3_expect=pm3_expect)
                    with open(a.state, "w") as f:
                        json.dump(st, f, indent=1)
                    print(f"    recorded -> {a.state}. Now move the tag to the Flipper and run"
                          f" --phase flipper --only {label}")
                    cue_move_to_flipper(label)
                    continue
            if a.phase == "both" and not a.no_prompt:
                # ⚠ A HEIGHT CHANGE MUST SOUND DIFFERENT FROM A PLAIN MOVE, or it gets missed -- and a
                # protocol read at the wrong gap is a false NO_READ. camp._cue already distinguishes
                # them: "lift & replace" + "move to '<n>mm'" gives the Tink cue and speaks
                # "reposition, N millimetres", and its _gap_phrase announces a gap only when it CHANGES,
                # so the six 6mm protocols in a row stay quiet instead of becoming noise to tune out.
                if gap != last_gap:
                    print(f"\n    ⚠⚠ HEIGHT CHANGE: {last_gap or '-'} -> {gap} ⚠⚠")
                    camp.ask(f">>> [Flipper] [{label}] lift & replace: move to '{gap}' at {gap}"
                             f" (expect {expect_name}), then press Enter: ")
                    last_gap = gap
                else:
                    camp.ask(f">>> [Flipper] [{label}] move the tag to the FLIPPER, keep the {gap} gap"
                             f" (expect {expect_name}), then press Enter: ")
            # ⚠ gap between invocations: back-to-back CLI calls intermittently fragment the heap until
            # the 97KB cli_rfid.fal cannot load (STATUS #20). Cheap insurance, not superstition.
            # ⚠ REPEAT, BEST-OF-N. One attempt is not a measurement at marginal coupling. The
            # justification is this project's OWN established finding, not anything seen while writing
            # this file: a refusal is a property of the PLACEMENT, and ~50% rates are normal at marginal
            # gap (block 0 read 32/70 at one untouched placement). A one-shot suite would report coupling
            # noise as a cross-build regression -- the exact false alarm this suite exists to prevent.
            # ⚠ DISAGREEMENT between attempts is its own finding: a miss is noise, but the same tag
            # decoding two DIFFERENT ways is a real defect and must not be hidden by best-of-N.
            attempts, port = read_attempts(
                port, max(1, a.attempts) if pm3_ok is not False else 0, a.deadline, reconnect,
                stop_after=a.stop_after)
            hits, name, data, raw, distinct, status = summarise_attempts(
                attempts, pm3_ok, allow_any=want.get("any_of"))
            ok = (name == expect_name)
            # identity: compare against what we ASKED the PM3 to write
            flds = rendered_fields(hits[0]["raw"]) if hits else {}
            pm3_id = pm3_identity(pm3_out, pm3_expect)
            id_ok, id_src = score_identity(pm3_clone, name, data, flds, pm3_id, want)
            id_checked = id_ok is not None
            if ok and id_ok is False:
                status = "WRONG_ID"
            recs.append(dict(build=a.build, firmware_commit=fw_commit, dirty_reason=a.allow_dirty, label=label, expect=expect_name, silicon=a.silicon,
                             position=(gap if a.position == 'auto' else a.position),
                             gap_window=gap,
                             attempts_cfg=a.attempts, suite_rev=SUITE_REV,
                             pm3_clone=pm3_clone, pm3_expect=pm3_expect,
                             pm3_verified=pm3_ok, pm3_out=pm3_out,
                             got_name=name, got_data=data, status=status, name_matches=ok,
                             fields=flds, want=want, id_checked=id_checked, id_ok=id_ok,
                             id_src=id_src, pm3_id=pm3_id,
                             n_attempts=len(attempts), n_read=len(hits),
                             distinct=sorted(f"{n} {d}" for n, d in distinct), raw=raw))
            flush()
            if status in ("WRONG_ID", "INCONSISTENT"):
                cue_fault("wrong identity" if status == "WRONG_ID" else "inconsistent reads")
            elif a.phase == "flipper":
                cue_move_to_pm3(label)
            print(f"    {status:12s} {len(hits)}/{len(attempts)} read  got={name!r} data={data!r}"
                  f" expected={expect_name!r}"
                  + ("" if name is None or ok else "   ⚠ PROTOCOL MISMATCH")
                  + ("" if id_ok is None else (f"   id OK via {id_src}" if id_ok else
                     f"   ⚠⚠ WRONG ID: wanted {want}, got data={data!r} fields={flds}"))
                  + ("   ⚠ NAME-ONLY: neither the PM3 nor the table gave a comparable"
                     " identity field" if hits and not id_checked else "")
                  + ("   ⚠⚠ SAME TAG DECODED DIFFERENTLY: " + str(sorted(distinct))
                     if len(distinct) > 1 else ""))
    finally:
        try:
            port.close()
        except Exception:
            pass
        flush()
    print(f"\nwrote {len(recs)} record(s) -> {out}")
    # ⚠ A SUMMARY THAT CANNOT OVERSTATE ITSELF. Count every bucket and name the unscored ones, because a
    # run that quietly reports "8 protocols read" while three were NO_READ is the §7.11 error again.
    from collections import Counter
    c = Counter(r["status"] for r in recs)
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())))
    weak = [r["label"] for r in recs if r["status"] == "READ" and not r.get("id_checked")]
    unsc = [r["label"] for r in recs if r["status"] in ("NO_READ", "INCONCLUSIVE")]
    if weak:
        print(f"  ⚠ NAME-ONLY (no identity comparison available): {', '.join(weak)}")
    if unsc:
        print(f"  ⚠ NOT SCORED, re-run these before claiming a complete pass: {', '.join(unsc)}")
    bad = [r["label"] for r in recs if r["status"] in ("WRONG_ID", "INCONSISTENT")]
    n_read = sum(1 for r in recs if r["status"] == "READ")
    if bad:
        print(f"  *** NEEDS ATTENTION: {', '.join(bad)}")
        cue_fault(f"suite finished with {len(bad)} failure{'s' if len(bad) != 1 else ''}: "
                  + ", ".join(bad))
    elif unsc:
        # finished, but something needs the operator back -- say WHICH, since that decides whether
        # they walk over now or later.
        cue_done(f"suite finished. {n_read} of {len(recs)} read. "
                 f"{len(unsc)} not scored: " + ", ".join(unsc), "Sosumi")
    elif recs:
        print("  all scored protocols read with a matching identity")
        cue_done(f"suite finished. {len(recs)} protocol{'s' if len(recs) != 1 else ''}, "
                 f"all read with a matching identity.", "Hero")
    print("⚠ NO_READ is not a failure and must not be compared as one -- re-seat and repeat.")


if __name__ == "__main__":
    main()
