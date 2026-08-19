[Back to the AetherProof README](../README.md)

# Getting started with AetherProof

**Who this is for:** anyone who needs to prove an AI's answer wasn't changed
afterwards. You do not need to be a programmer. If you can copy and paste a line
into a terminal, you can use this.

If you *are* a developer and want the API, skip to the [README](../README.md).

---

## The problem, in one paragraph

An AI writes something - a summary, a decision, a diagnosis, a legal note. Weeks
later someone asks: *"is that really what it said, or did somebody edit it?"*
Right now there is usually no way to tell. A text file can be changed and looks
identical afterwards.

AetherProof gives you a **receipt**. It's a small file that acts like a wax seal:
if even one character of the answer changes, the seal breaks and anyone can see
it broke.

**What it proves:** this exact text existed at this time and has not been altered.
**What it does not prove:** that the AI was telling the truth. A receipt for a
wrong answer is still a valid receipt for a wrong answer. It proves the *record*,
not the *content*.

That distinction matters and we would rather say it plainly than oversell.

---

## Install it

You need Python 3.9 or newer. To check, open a terminal and type:

```
python --version
```

If that prints a version number, you're fine. Then:

```
pip install aetherproof
```

That's the whole installation.

---

## Your first receipt in three steps

Say an AI just answered a question for you.

**Step 1 - save the question and the answer as two text files.**

`question.txt`
```
What was our Q3 refund policy?
```

`answer.txt`
```
Refunds were accepted within 30 days with a receipt.
```

**Step 2 - make the receipt.**

```
aetherproof sign --input question.txt answer.txt
```

You'll see a confirmation and a file path. That path is your receipt - keep it
somewhere safe, like any other important document.

> **If you have the AI model's own file**, put it first:
> `aetherproof sign model.onnx answer.txt --input question.txt`. That's a
> stronger receipt. Most people using a cloud AI don't have that file, and that
> is fine - see [When you use a cloud AI](#when-you-use-a-cloud-ai-chatgpt-claude-gemini).

**Step 3 - check it any time, forever.**

```
aetherproof verify <path-to-your-receipt> --output answer.txt
```

If everything is intact you'll see:

```
 VALID - signature intact AND output file matches the receipt.
```

Try it: open `answer.txt`, change one word, save, and run verify again:

```
Error: OUTPUT MODIFIED - the output file does not match this receipt.
```

That is the entire point. (For scripts: it exits `0` when valid, `1` when not.)

---

## The one thing worth understanding

There are two files that matter:

| File | What it is | Can you share it? |
|---|---|---|
| `signing_key.pem` | Your **private** key - the wax stamp | **Never.** Anyone with this can forge your receipts. |
| `signing_key.pub` | Your **public** key - the shape of the seal | Yes. Share it freely; people need it to check your receipts. |

Both live in a folder called `.aetherproof` inside your home directory.

**If you lose the private key**, you can't make new receipts under the same
identity - but every receipt you already made still checks out. Old receipts only
need the *public* key.

**If someone steals the private key**, they can forge receipts as you. Treat it
like a password. To add a password to the key itself, see
[Protecting your key](#protecting-your-key) below.

---

## Checking someone else's receipt

Someone hands you a receipt and claims an AI produced a certain text. You need:

1. their receipt file (`ap_xxxx.json`)
2. their public key (`ap_xxxx.pub`, usually sitting next to it)
3. the text you're checking

```
aetherproof verify ap_xxxx.json --output the-text-they-gave-you.txt
```

**No internet needed. No account. No permission from us.** That is deliberate -
if checking a receipt required our servers, then our servers would be the thing
you had to trust, and the whole point would be gone.

It will still work in twenty years, whether or not this project still exists.

---

## When you use a cloud AI (ChatGPT, Claude, Gemini)

You cannot download those models. They live on the provider's computers. So
AetherProof **cannot** prove which model produced the text, and it will not claim
to. Anyone telling you otherwise is overstating what is possible.

What it *does* prove is the part you're actually responsible for: the exact
question you sent, the exact answer you acted on, when it happened, and that none
of it was altered afterwards. In a real dispute the argument is almost never
"was it GPT-4 or GPT-4-turbo" - it's **"did the AI actually say this, or was the
record edited later?"** That question AetherProof answers completely.

The receipt labels this honestly as `api_attested` rather than pretending.

---

## Common questions

**Do I need to be online?**
Only to install. Making and checking receipts works completely offline.

**Does my text get uploaded anywhere?**
No. Nothing leaves your computer. Receipts store a *fingerprint* of your text
(a hash), never the text itself - so a receipt can be shared without revealing
what it covers.

**What if I have thousands of AI answers?**
See [Sealing a whole conversation](#sealing-a-whole-conversation) below.

**Can I prove the AI's answer was correct?**
No, and be wary of anything claiming otherwise. This proves the record is
unaltered, not that the content is true.

**What if AetherProof disappears?**
Receipts use standard, public cryptography (SHA-256 and Ed25519). Any programmer
can check one with ordinary tools and no AetherProof code at all - the README has
a 20-line example. That's on purpose.

**Where are my files?**
In `.aetherproof` in your home directory. To put them elsewhere, set
`AETHERPROOF_HOME` to a folder path.

---

## Sealing a whole conversation

Making one receipt per message gets unwieldy fast. Instead you can seal an entire
conversation with a **single** signature, then later prove any one message from it
without revealing the others.

That last part matters for privacy: if a regulator asks about message 457, you can
prove that one message and hand over nothing else.

```python
from aetherproof.auto import AutoSession

with AutoSession(model_id="claude-opus-5") as chat:
    chat.turn(prompt="What was our Q3 refund policy?",
              output="Refunds were accepted within 30 days with a receipt.")
    chat.turn(prompt="And Q4?",
              output="Q4 extended it to 60 days.")

# one seal now covers the whole conversation
proof = chat.prove(0)          # prove just the first exchange
```

A thousand-message conversation still produces one small seal, and proving any
single message takes about ten short numbers rather than the whole transcript.

---

## Protecting your key

By default the private key is stored unprotected, relying on your computer's file
permissions. **On Windows those permissions do not meaningfully protect it** - we
tested this rather than assumed it.

To protect the key with a password, set this before using AetherProof:

```
# macOS / Linux
export AETHERPROOF_KEY_PASSPHRASE="choose something long"

# Windows PowerShell
$env:AETHERPROOF_KEY_PASSPHRASE = "choose something long"
```

The key is then encrypted on disk. **If you forget this password the key cannot be
recovered** - but, again, receipts you already made stay verifiable, because
checking only needs the public key.

Set it before your first use, or the key will already have been created
unprotected.

---

## For automated setups

If you're wiring this into a script, CI job, or an AI agent that runs unattended,
use `aetherproof.auto` - it never prompts and never blocks:

```python
from aetherproof.auto import sign
sign(prompt="...", output="...", model_id="gpt-4o")
```

| Setting | What it does |
|---|---|
| `AETHERPROOF_HOME` | Where keys and receipts are stored |
| `AETHERPROOF_KEY_PASSPHRASE` | Password-protects the key |
| `AETHERPROOF_DISABLE=1` | Turns receipt-making off entirely |
| `AETHERPROOF_STRICT=1` | Fail loudly instead of continuing quietly |

By default, if a receipt can't be written the rest of your program carries on -
losing a receipt is bad, but crashing a production job over one is worse. Set
`AETHERPROOF_STRICT=1` where a missing receipt is itself the failure.

---

## Getting help

- **What this can and cannot prove:** [CLAIMS.md](CLAIMS.md) - a deliberately
  honest list, including the limitations.
- **All commands:** `aetherproof --help`
- **Bugs and questions:** https://github.com/pulkit6732/aetherproof/issues
