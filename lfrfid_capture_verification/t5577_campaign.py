#!/usr/bin/env python3
"""SUBSET of the T5577 research harness, extracted mechanically -- ONLY the helpers `lf_suite.py`
imports (`open_port`, `run_cmd`, `pm3_exec`, `parse_dump_blocks`, `ask`, `_cue`) plus their transitive
dependencies. The full 1713-line module is unrelated to this verification and is not included, so
`lf_suite.py` here is BYTE-IDENTICAL to the file that produced the artefacts rather than edited to
drop an import. Extracted from t5577_campaign.py; every function below is verbatim.
"""
import argparse

import glob

import json

import os

import re

import shlex

import subprocess

import sys

import time

from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

class Colour:
    CODES = {"ok": "1;32", "err": "1;31", "warn": "1;33", "info": "1;36", "head": "1;35", "dim": "2",
             # distinct per physical action: magenta=go to Proxmark, cyan=go to Flipper, blue=reposition
             "pm3": "1;35", "flip": "1;36", "repos": "1;34"}

    def __init__(self, enabled=False):
        self.enabled = enabled

    def __call__(self, kind, s):
        code = self.CODES.get(kind)
        return "\033[%sm%s\033[0m" % (code, s) if (self.enabled and code) else s

C = Colour(False)  # .enabled is set in main() once we know the tty / --no-color / NO_COLOR

def clean(s):
    return _ANSI.sub("", s).replace("\r", "")

def at_prompt(raw):
    t = clean(raw).rstrip()
    return t.endswith(">") or t.endswith(">:")

def toolchain_python():
    """fbt provisions its own Python (with pyserial) to talk to the Flipper. Find it, so we can tell the
    operator which interpreter to use rather than leaving them on the byte-dropping fallback."""
    for rel in ("toolchain/arm64-darwin/bin/python3", "toolchain/x86_64-darwin/bin/python3",
                "toolchain/x86_64-linux/bin/python3", "toolchain/current/bin/python3"):
        cand = os.path.join(HERE, "..", rel)
        if os.path.isfile(cand):
            return os.path.normpath(cand)
    return None

def open_port(path):
    """Return (port, backend); port has .reset()/.write(bytes)/.read()->bytes/.close()."""
    try:
        import serial  # pyserial
    except ImportError:
        serial = None
    if serial is None:
        # ⚠ THE FALLBACK SILENTLY DROPS BYTES. It is a raw tty read through select() with no flow
        # control: at 115200 any stall past ~35ms loses data, and a `sweepstat 15 dump` ships ~90KB.
        # Device-observed 2026-08-16: 12 of 21 captures in one batch had characters missing --
        # "MEASUREENT", "rery phase", "attemt" -- including inside the maxblock vote counts an
        # experiment depended on, which cost a whole batch. The captures were still ~98% usable, but
        # the summary text was not, and you cannot tell which numbers were eaten.
        tp = toolchain_python()
        print(C("err", "!! pyserial NOT available -- falling back to a raw tty that DROPS BYTES under load."))
        if tp:
            print(C("warn", "   fbt already ships a Python with pyserial. Re-run with:"))
            print(C("info", "     %s %s <same args>" % (tp, os.path.relpath(os.path.abspath(__file__)))))
        else:
            print(C("warn", "   Install pyserial, or run under fbt's toolchain Python."))
        if not ask_choice(C("warn", "   Continue anyway on the lossy fallback? [y/N] "), "yn", "n") == "y":
            sys.exit(C("err", "Aborted -- re-run with a Python that has pyserial."))
    if serial is not None:
        # ⚠⚠ write_timeout IS NOT OPTIONAL. Without it pyserial's flush() calls termios.tcdrain(),
        # which blocks FOREVER when the device stops draining its USB CDC OUT endpoint -- and the
        # Flipper does exactly that whenever its CLI thread is stuck, e.g. while the LF RFID GUI app
        # holds the LF worker. A run hung solid on writing a single Ctrl+C byte, with no timeout and
        # no error, and had to be killed by hand. The read path always had a deadline; the WRITE path
        # had none. With a timeout it raises instead, and read_attempts' existing reconnect handles it.
        s = serial.Serial(path, 115200, timeout=0.2, write_timeout=10)  # baud ignored by USB-CDC

        class P:
            def reset(self):
                s.reset_input_buffer()

            def write(self, b):
                s.write(b); s.flush()

            def read(self):
                return s.read(4096)

            def close(self):
                s.close()

        # ⚠⚠ DRAIN THE CONNECT BANNER BEFORE HANDING THE PORT OVER. A fresh USB-CDC session makes
        # the Flipper emit its welcome text ending in "\r\n>: ", and that banner RACES the first
        # command: run_cmd resets the input buffer, writes the command, and can then terminate on the
        # BANNER's prompt -- returning the banner as if it were the command's output. device_info came
        # back with no firmware_commit at all this way, which reads as "unknown build" and correctly
        # aborts the run. It matters more now that the suite reconnects mid-run after the operator has
        # driven the GUI: every reconnect starts a new session, so every reconnect hits this.
        p = P()
        start = last = time.time()
        while time.time() - start < 3.0:          # hard cap
            if p.read():
                last = time.time()
            elif time.time() - last > 0.3:        # 300ms of quiet == banner finished
                break
        p.reset()
        return p, "pyserial"

    import termios, tty, select
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)

    class P:
        def reset(self):
            try:
                termios.tcflush(fd, termios.TCIFLUSH)
            except Exception:
                pass

        def write(self, b):
            os.write(fd, b)

        def read(self):
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    return os.read(fd, 4096)
                except OSError:
                    return b""
            return b""

        def close(self):
            try:
                os.close(fd)
            except Exception:
                pass

    return P(), "stdlib-termios"

def run_cmd(port, cmd, max_s, progress=None, fault_cue=True):
    """fault_cue=False for internal probes. The startup `run_cmd(port, "", 5)` prompt-sync sends an EMPTY
    command and discards its result, so on a silent device it 'times out' with zero bytes by design -- and
    with fault_cue on it announced 'no response, check if the flipper is locked' out loud, on top of the
    PM3 cue, from a call that was never a capture. Only real captures should report a fault."""
    """Send one Flipper CLI command; capture output until the prompt returns (or max_s)."""
    port.reset()
    port.write((cmd + "\r").encode())
    buf = bytearray()
    start = time.time()
    timed_out = True
    last_tick = 0.0
    while time.time() - start < max_s:
        if progress and time.time() - last_tick >= 1.0:
            progress()
            last_tick = time.time()
        chunk = port.read()
        if chunk:
            buf += chunk
            # ⚠ CHECK ONLY THE TAIL. This used to hand at_prompt() the ENTIRE accumulated buffer on every
            # chunk, and at_prompt runs an ANSI regex over what it is given -- so a 125KB `sweepstat 15
            # dump` did O(n^2) character work, gigabytes of it. While Python was busy doing that it was NOT
            # reading the serial port, the driver buffer overflowed, and BYTES WERE SILENTLY DROPPED.
            # Device-observed 2026-08-17: 12 of 21 captures in one batch had characters missing
            # ("MEASUREENT", "rery phase", "attemt"), including inside the maxblock vote counts the whole
            # experiment depends on. The prompt only ever appears at the END, so the tail is all that
            # matters and this is O(n).
            if at_prompt(bytes(buf[-256:]).decode("utf-8", "replace")):
                time.sleep(0.15)
                buf += port.read()
                timed_out = False
                break
    text = clean(bytes(buf).decode("utf-8", "replace")).strip()
    if timed_out:
        # ⚠ ZERO BYTES IS A DIFFERENT FAULT FROM A TRUNCATED CAPTURE, AND SAYING "TIMED OUT" FOR BOTH SENDS
        # YOU AFTER THE WRONG THING. A truncated capture means the budget was too small. ZERO bytes means the
        # device never answered at all -- and the cause observed TWICE on 2026-08-18 is simply that the
        # FLIPPER WAS LOCKED: the port still enumerates, so everything looks connected, and every command
        # returns nothing. The first time it was misread as a flash failure (two `flash_usb_full` runs died
        # at "Installing"); the second time it burned two captures and a debugging detour. An open CLI
        # session elsewhere produces the same silence, because macOS lets two readers share /dev/cu.* and the
        # other one consumes the replies.
        if not text and fault_cue:
            text = ("[!! NO RESPONSE AT ALL from the Flipper in %ds -- 0 bytes.\n"
                    "    This is almost certainly NOT a timeout. Check, in order:\n"
                    "      1. IS THE FLIPPER LOCKED? Unlock it. A locked device enumerates but answers nothing.\n"
                    "      2. Is another CLI/serial session open on the same port? Close it.\n"
                    "      3. Is the screen showing a crash or an update prompt?\n"
                    "    Nothing was captured, so this reposition must be REDONE -- do not keep the file.]" % max_s)
        else:
            text += "\n[!! capture TIMED OUT after %ds -- output may be incomplete]" % max_s
        # ⚠ A TIMEOUT MUST BE AUDIBLE. _cue() fires on the PROMPTS that ask the operator to do something,
        # and a timeout is not a prompt -- so the one event that silently ruins a capture was the only one
        # with no sound. Device-observed 2026-08-18: the operator missed the first of two consecutive
        # timeouts because the run just carried on to the next reposition. Distinct sound (Basso) and
        # wording from every other cue, because this one means STOP, not "move the tag".
        if SOUND and fault_cue:
            sys.stdout.write("\a\a")
            sys.stdout.flush()
            try:
                subprocess.Popen(["afplay", "/System/Library/Sounds/Basso.aiff"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        if SPEAK and fault_cue:
            try:
                subprocess.Popen(["say", "-r", "200",
                                  "no response, check if the flipper is locked" if not buf
                                  else "capture timed out"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
    return text

def pm3_exec(pm3_bin, cmds, split, timeout=90):
    """Run a list of pm3 commands; return combined stdout+stderr text. cmds batched with ';' unless split."""
    base = shlex.split(pm3_bin)
    out = ""
    groups = [[c] for c in cmds] if split else [cmds]
    for g in groups:
        joined = " ; ".join(g)
        try:
            r = subprocess.run(base + ["-c", joined], capture_output=True, text=True, timeout=timeout)
            out += (r.stdout or "") + (r.stderr or "")
        except subprocess.TimeoutExpired:
            out += "\n[pm3 TIMED OUT after %ss -- client waiting for the Proxmark3 (device busy/absent?)]\n" % timeout
        except Exception as e:
            out += "\n[pm3 ERROR running '%s': %s]\n" % (joined, e)
    return out

def parse_dump_blocks(text):
    """Parse `lf t55xx dump` PAGE-0 rows ('  00 | 000880E8 | ...') into {blocknum: hex}.

    ⚠ PAGE-AWARE ON PURPOSE. This used to take the FIRST occurrence of each block number, on the reasoning
    that page 0 is printed first. That silently falls through to PAGE 1 whenever a page-0 row is missing or
    malformed -- and on 2026-08-19 it did exactly that, reporting a page-1 traceability word as the value
    of page-0 block 1 and failing a write verification for a write that had probably succeeded. A defective
    dump must read as UNREADABLE, never as the wrong page's data: absence is recoverable (retry), a
    plausible wrong value is not (it mislabels the corpus).
    """
    out = {}
    # Everything from the Page 0 header up to the Page 1 header, when those markers are present.
    m0 = re.search(r"Page\s*0(.*?)(?=Page\s*1|\Z)", text, re.S)
    scope = m0.group(1) if m0 else text
    for m in re.finditer(r"(?m)^\s*(?:\[\+\]\s*)?(\d\d)\s*\|\s*([0-9A-Fa-f]{8})\s*\|", scope):
        b = int(m.group(1))
        if b not in out and b <= 7:
            out[b] = m.group(2).upper()
    return out

SOUND = True

SPEAK = True

_LAST_GAP = None

def _spoken(s):
    """Expand units so `say` pronounces them as words rather than letters ('3mm' -> '3 millimetres')."""
    return re.sub(r"([0-9.]+)\s*mm\b", r"\1 millimetres", s)

def _gap_phrase(plain):
    """The declared air gap in this prompt, or '' if it has not changed since it was last spoken."""
    global _LAST_GAP
    m = (re.search(r"\bat ([0-9.]+\s*mm)\b", plain)
         or re.search(r"\bkeep the ([0-9.]+\s*mm) gap", plain))
    if not m:
        return ""
    g = m.group(1).replace(" ", "")
    if g == _LAST_GAP:
        return ""
    _LAST_GAP = g
    return ", at " + _spoken(g)

def _cue(msg):
    if not (SOUND or SPEAK):
        return
    plain = _ANSI.sub("", msg)
    if "[PM3 re-verify]" in plain:
        snd, words = "Submarine", "back to Proxmark"
    elif "[PM3]" in plain:
        snd, words = "Submarine", "Proxmark"
    elif "[Flipper]" in plain:
        # ...and name the position too, when there is one: with --positions the label IS the variable
        # under test, so "move to Flipper" alone tells the operator nothing about what to do.
        pm = re.search(r"position '([^']+)'", plain)
        snd = "Glass"
        words = "move to Flipper"
        if pm:
            words += ", " + _spoken(pm.group(1).replace("-", " "))
        words += _gap_phrase(plain)
    elif "lift & replace" in plain:
        m = re.search(r"move to '([^']+)'", plain)
        snd = "Tink"
        words = ("reposition, " + _spoken(m.group(1).replace("-", " "))) if m else "reposition"
        words += _gap_phrase(plain)
    else:
        return
    if SOUND:
        sys.stdout.write("\a")          # terminal bell, works anywhere
        sys.stdout.flush()
        try:                            # macOS: an actually audible tone
            subprocess.Popen(["afplay", "/System/Library/Sounds/%s.aiff" % snd],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    if SPEAK:
        try:
            subprocess.Popen(["say", "-r", "220", words],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

def ask(msg):
    _cue(msg)
    try:
        input(msg)
    except EOFError:
        pass

def ask_choice(msg, choices, default):
    """Prompt for a single-letter choice; return default on empty/EOF."""
    while True:
        try:
            r = input(msg).strip().lower()
        except EOFError:
            return default
        if not r:
            return default
        if r[0] in choices:
            return r[0]
        print("  (enter one of: %s)" % ", ".join(choices))

