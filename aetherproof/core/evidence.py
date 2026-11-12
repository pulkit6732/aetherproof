"""Evidence package: a stored reconciliation run, sealed so a third party can check it.

The package carries the full run (every verdict, reason, signed-instruction summary and the
hash of every provider and bank record behind it) plus an Ed25519 signature over its
canonical digest. Anyone holding the originator's public key, obtained separately and not
from the package, can confirm offline that nothing in it was changed after export.
"""

import json
from typing import Dict, List, Tuple

from .hash import sha256
from .log import _as_keyring
from .receipt import Receipt
from .reconcile import canonical_json

FORMAT = "aetherproof.evidence/v1"


def _digest(run: Dict) -> str:
    return sha256(canonical_json(run))


def export_package(run: Dict, signer) -> Dict:
    digest = _digest(run)
    return {"format": FORMAT, "run": run, "digest": digest,
            "signing_key_id": Receipt.key_id(signer.get_public_key()), "signature": signer.sign(digest.encode())}


def verify_package(pkg: Dict, public_keys) -> Tuple[bool, List[str]]:
    """(ok, problems). Fails closed: any missing field, unknown key or changed byte is a problem."""
    problems: List[str] = []
    if not isinstance(pkg, dict) or pkg.get("format") != FORMAT:
        return False, [f"not an evidence package (expected format {FORMAT})"]
    run = pkg.get("run")
    if not isinstance(run, dict):
        return False, ["package has no run"]
    if _digest(run) != pkg.get("digest"):
        problems.append("run content does not match the sealed digest: the package was modified after export")
    key = _as_keyring(public_keys).get(pkg.get("signing_key_id"))
    if key is None:
        problems.append(f"no trusted key for signing_key_id={pkg.get('signing_key_id')}")
    elif not key.verify(str(pkg.get("digest", "")).encode(), str(pkg.get("signature", ""))):
        problems.append("signature does not verify under the trusted key")
    return not problems, problems


def load_package(path) -> Dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
