"""The README's "verify without AetherProof" snippet must actually work.

That snippet is the project's central claim made concrete: a receipt can be
checked with a standard crypto library and no AetherProof code, so the format
outlives the tool. If it drifts out of date it is worse than no example — a
reader concludes the format is undocumented or the signatures are broken.

It HAD drifted: v1.3 added receipt_id and signing_key_id to the preimage while
the README still listed the nine v1.1 fields, so the snippet failed against
every receipt the current version produces.

These tests extract the code from README.md and run it, so the documentation
cannot silently rot again.
"""

import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer

README = Path(__file__).resolve().parents[1] / "README.md"


def readme_preimage(r: dict) -> bytes:
    """Independent reimplementation of the README's documented procedure.

    Deliberately written from the README's prose rather than by importing
    Receipt.canonical_message — importing it would make this test pass even if
    the documented procedure were wrong, which is the whole thing being checked.
    """
    fields = [
        r["receipt_version"], r["model_weight_root"], r["model_root_type"],
        r["input_commitment"], r["output_hash"], str(r["timestamp_ms"]),
        str(r["log_sequence"]),
        json.dumps(r["hw_evidence"], sort_keys=True, separators=(",", ":")),
        r["log_anchor"],
    ]
    if r["receipt_version"] not in ("1.0", "1.1", "1.2"):
        fields += [r["receipt_id"], r["signing_key_id"]]
    if r.get("signed_extensions"):
        def canon(o):
            return json.dumps(o, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        leaves = sorted(
            hashlib.sha256(canon(ns) + canon(body)).hexdigest()
            for ns, body in r["signed_extensions"].items()
        )
        agg = hashlib.sha256("".join(leaves).encode("utf-8")).hexdigest()
        fields.append(f"sha256:{agg}")
    return "".join(f"{len(f)}:{f}" for f in fields).encode("utf-8")


@pytest.fixture
def signer():
    return Signer.generate()


def signed(signer, **kw):
    base = dict(model_weight_root="a" * 64, model_root_type="artifact_hash",
                input_commitment="b" * 64, output_hash="c" * 64,
                log_sequence=1, log_anchor="local://log/1",
                signing_key_id=Receipt.key_id(signer.get_public_key()))
    base.update(kw)
    r = Receipt(**base)
    r.signature = signer.sign(r.signing_bytes())
    return r


def check(receipt, signer):
    """Verify exactly as an outside party following the README would."""
    r = json.loads(receipt.to_json())
    pub = load_pem_public_key(signer.get_public_key().export_public_pem())
    pub.verify(bytes.fromhex(r["signature"]), readme_preimage(r))   # raises if wrong
    return True


# ══ the documented procedure verifies real receipts ═════════════════════════

def test_v13_receipt_verifies_by_the_documented_procedure(signer):
    assert check(signed(signer), signer) is True


def test_v13_with_extensions_verifies(signer):
    r = signed(signer, signed_extensions={
        "org.aetherproof.session/v0.1": {"session_id": "s_1", "turn_index": "3"}})
    assert check(r, signer) is True


def test_v13_with_several_extension_namespaces_verifies(signer):
    r = signed(signer, signed_extensions={
        "org.aetherproof.session/v0.1": {"session_id": "s_1"},
        "org.liminal.agent_chain/v0.1": {"actor_id": "agent:planner"}})
    assert check(r, signer) is True


@pytest.mark.parametrize("version", ["1.1", "1.2"])
def test_legacy_receipts_still_verify_by_the_documented_procedure(signer, version):
    """Old receipts in an auditor's hands must keep working."""
    ext = {"ns/v1": {"a": "b"}} if version == "1.2" else {}
    r = signed(signer, receipt_version=version, signed_extensions=ext,
               timestamp_ms=1_700_000_000_000)
    assert check(r, signer) is True


def test_documented_preimage_matches_the_implementation(signer):
    """The README and canonical_message must agree byte for byte."""
    r = signed(signer)
    assert readme_preimage(json.loads(r.to_json())) == r.signing_bytes()


def test_documented_preimage_matches_for_legacy_versions(signer):
    for version in ("1.1", "1.2"):
        ext = {"ns/v1": {"a": "b"}} if version == "1.2" else {}
        r = signed(signer, receipt_version=version, signed_extensions=ext)
        assert readme_preimage(json.loads(r.to_json())) == r.signing_bytes(), version


def test_tampering_is_caught_by_the_documented_procedure(signer):
    from cryptography.exceptions import InvalidSignature
    r = json.loads(signed(signer).to_json())
    r["output_hash"] = "f" * 64
    pub = load_pem_public_key(signer.get_public_key().export_public_pem())
    with pytest.raises(InvalidSignature):
        pub.verify(bytes.fromhex(r["signature"]), readme_preimage(r))


def test_a_rewritten_receipt_id_is_caught(signer):
    """The v1.3 addition — the reason the snippet had to change."""
    from cryptography.exceptions import InvalidSignature
    r = json.loads(signed(signer).to_json())
    r["receipt_id"] = "ap_00000000"
    pub = load_pem_public_key(signer.get_public_key().export_public_pem())
    with pytest.raises(InvalidSignature):
        pub.verify(bytes.fromhex(r["signature"]), readme_preimage(r))


# ══ the README text itself stays in sync ════════════════════════════════════

def test_readme_snippet_mentions_the_v13_fields():
    text = README.read_text(encoding="utf-8")
    block = text.split("rebuild the injective preimage")[1][:1200]
    assert 'r["receipt_id"]' in block
    assert 'r["signing_key_id"]' in block


def test_readme_snippet_still_handles_legacy_versions():
    text = README.read_text(encoding="utf-8")
    block = text.split("rebuild the injective preimage")[1][:1200]
    assert '"1.1"' in block and '"1.2"' in block


def test_readme_snippet_is_valid_python():
    """Extract the documented code and compile it."""
    text = README.read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)```", text, re.S)
    snippet = next(b for b in blocks if "rebuild the injective preimage" in b)
    compile(snippet, "README.md", "exec")


def test_readme_does_not_claim_an_unimplemented_signature_scheme():
    """Ed25519 only. ML-DSA is roadmap, and CLAIMS.md says so."""
    text = README.read_text(encoding="utf-8").lower()
    for line in text.splitlines():
        if "ml-dsa" in line:
            assert "signet" in line, f"ML-DSA claimed for AetherProof: {line!r}"
