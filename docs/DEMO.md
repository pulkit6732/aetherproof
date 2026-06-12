# AetherProof — Demo Shoot Guide (on-camera)

A detailed plan for filming the demo on a fresh laptop: how to prepare the
machine, what to put on camera, what to keep off camera, the exact beats
(CLI + the interactive UI), and the narration. The whole film is ~2 minutes.

The one thing the audience must believe: **you cannot change an AI's output, or
quietly rewrite the record of it, without it being caught — offline, by anyone.**

---

## 0. PREPARE THE LAPTOP (do this BEFORE recording)

> ⚠️ A brand-new laptop has **no Python**, so nothing here runs out of the box,
> and `pip install aetherproof` does **not** work yet (not published to PyPI).
> Pick ONE of these and do it **off camera**:

**Path A — pre-install (fastest).** On the demo laptop, before filming:
1. Install Python 3.9+ (python.org installer; tick "Add to PATH").
2. Copy the `aetherproof` project folder onto the laptop (USB / download).
3. In a terminal: `pip install .` from inside that folder.
4. Verify it works: `aetherproof --help` shows the command table.
Then record only the *product* (Section 3) — the audience never sees the install.

**Path B — standalone executable (no Python at all).** Build a one-file binary
(`pyinstaller --onefile -n aetherproof aetherproof/__main__.py`) on a build
machine, copy the single `aetherproof.exe` to the laptop, and run it directly.
This is the honest match for "new laptop, nothing installed." (Ask if you want
this built.)

**Path C — real install on camera.** Only if the repo is pushed and on PyPI:
`pipx install aetherproof`. Still needs Python on the laptop.

**Recommended:** Path A to film today; Path B if "runs on any laptop with zero
install" is part of the story.

Also do this off camera before recording, for a clean "first run" look:
```bash
rm -rf ~/.aetherproof        # remove any existing signing key (fresh-machine look)
mkdir demo && cd demo        # work in a clean folder
```

---

## 1. SCREEN HYGIENE — what to show and what NOT to show

It is a **security** product; sloppy screen = lost trust. Before recording:

DO show:
- A clean terminal, large font, dark theme.
- The receipt JSON, the green VALID panel, the red OUTPUT MODIFIED / FAILED lines.
- The `aetherproof` interactive menu.
- That verification is **offline** (you can unplug Wi-Fi and it still works — a
  great on-camera beat).

DO NOT show (blur, close, or move off screen):
- **The private key file contents.** Never `cat ~/.aetherproof/signing_key.pem`.
  You may *say* "the private key stays on this machine," but never display it.
- Any internal tooling, planning notes, sales material, or private working
  folders that are not part of the open-source package.
- Desktop clutter, other app windows, browser tabs, email, chat notifications.
  Turn on Do Not Disturb / focus mode.
- Any real customer data — use the neutral sample text in this guide.
- File paths that reveal your name/machine if that matters to you (or accept it).

---

## 2. WHAT YOU'RE DEMONSTRATING (the three beats)

1. **Sign** — put a receipt on an AI output.
2. **Tamper the output** — the receipt catches it.
3. **Tamper the log** — the transparency log catches that too.

Film the **interactive UI** for beats 1–2 (looks friendly, non-technical), and
drop to the **CLI** for the log-tamper beat (beat 3) because it's the most
technical and convincing. You can do the whole thing in the CLI if you prefer
speed — both scripts are below.

---

## 3. THE SHOT LIST

### Take 1 — the friendly UI (beats 1 and 2)

| # | On camera | You type / do | What's visible | Narration (one line) |
|---|---|---|---|---|
| 1 | Terminal, clean folder | `aetherproof` | The ASCII logo + the menu (Sign / Verify / …) | "This is AetherProof — it puts a tamper-proof receipt on any AI output." |
| 2 | Menu | arrow to **Sign an AI output**, Enter | Model picker appears | "I'll sign an output. Pick the model that produced it." |
| 3 | Model picker | choose **GPT-4o** (or Custom…) | Prompt: paste the output | — |
| 4 | Paste prompt | type/paste: `The patient shows no signs of malignancy.` then blank line | 4-step progress bar runs | "It hashes the output, signs it, and logs it." |
| 5 | Success panel | (nothing) | Green **RECEIPT SIGNED** panel: receipt id, output hash, log entry #000001, saved path | "Here's the receipt — proof this exact text came from this model." |
| 6 | "Next" prompt | choose **Verify this receipt** | Green **VALID** panel | "Anyone can verify it — offline, with just the public key." |
| 7 | (optional, strong) | unplug Wi-Fi / turn it off, verify again | Still VALID | "No internet. No server. It still verifies." |

### Take 2 — tamper the output (beat 2, the kill shot)

Switch to a terminal in the same `demo` folder.

| # | On camera | You type | What's visible | Narration |
|---|---|---|---|---|
| 8 | terminal | `RID=$(ls receipts/*.json \| head -1 \| xargs -n1 basename \| sed 's/.json//')` | (nothing) | "Here's the output file the AI produced…" |
| 9 | open the output file in an editor | change `no signs` → `signs` and save | the edited text | "…and here's an attacker editing it — flipping the diagnosis." |
| 10 | terminal | `aetherproof verify receipts/$RID.json --output <the file>` | red **OUTPUT MODIFIED — the output file does not match this receipt** | "Caught. The receipt is intact, but the output was changed — and verification fails." |

> Pause ~1.5s on the red line. That frame is the pitch.

### Take 3 — tamper the log (beat 3, for the technical viewer)

| # | On camera | You type | What's visible | Narration |
|---|---|---|---|---|
| 11 | terminal | sign two more outputs (any text), then `aetherproof log verify` | green "Log integrity verified — 3 receipts… no gaps." | "Every receipt also goes into an append-only log." |
| 12 | terminal | run the delete-then-renumber (one line below) | (nothing) | "Now I delete a record from the log and renumber the rest to hide the gap…" |
| 13 | terminal | `aetherproof log verify` | red **Log integrity check FAILED** | "…and the log still catches it. You can't quietly rewrite history." |

The attack line (paste as-is):
```bash
python -c "import sqlite3; c=sqlite3.connect('receipts/log.db'); \
c.execute('DELETE FROM receipts WHERE sequence=2'); \
c.execute('UPDATE receipts SET sequence=sequence-1 WHERE sequence>2'); \
c.commit(); c.close()"
```

### Optional closer — pipe to jq (developer audience)
```bash
aetherproof verify receipts/$RID.json --output thefile.txt --quiet | jq .valid   # -> false
```
"It's a clean exit code and JSON, so it drops straight into CI."

---

## 4. RECORDING SETUP

- **Font:** 18–22pt, dark theme, terminal width ~90 columns so text is legible in playback.
- **The UI menu needs a screen recorder** (OBS / QuickTime / Xbox Game Bar) — the
  arrow-key menu is interactive and won't capture as plain text.
- **The CLI-only beats** can use **asciinema** for a crisp, copy-pasteable cast:
  `asciinema rec demo.cast` → run the commands → `Ctrl-D` → `asciinema upload demo.cast`.
- Hide the cursor blink distractions; type at a calm pace; let panels finish drawing.
- Total runtime target: **90–120 seconds**.

---

## 5. NARRATION SCRIPT (read straight through)

1. "This is AetherProof. It puts a tamper-proof receipt on any AI output."
2. "I sign an output — here, a medical note. It hashes it, signs it, logs it."
3. "Anyone can verify that receipt offline, with just a public key. Valid."
4. "Now watch: an attacker edits the output but leaves the receipt alone."
5. "Verification fails — output modified. The proof caught the change."
6. "And the log itself is tamper-proof: I delete a record and renumber to hide
   it, and verification still fails. No server, no trust in me — just math."

---

## 6. RESET BETWEEN TAKES
```bash
cd .. && rm -rf demo && mkdir demo && cd demo   # fresh receipts + log
# to also reset the signing key (true fresh-machine look):
rm -rf ~/.aetherproof
```

---

## 7. HONEST FRAMING (so you don't overclaim on camera)
Say: "proves the output wasn't changed and the record wasn't rewritten, verifiable
offline." Do **not** say it proves the model actually ran, or that the key is in
hardware — that's the next layer (Signet). The full proves / does-not-prove
matrix is in `CLAIMS.md`; keep claims at that level and the demo stays bulletproof.
