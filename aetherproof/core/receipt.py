"""Receipt dataclass and canonical field definitions."""

from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any
import hashlib
import json
import secrets
from datetime import datetime

# Receipt versions whose signing preimage predates the v1.3 hardening pass.
# Their builders are kept verbatim so receipts already issued to third parties
# keep verifying; only newly-minted receipts use v1.3.
LEGACY_VERSIONS = ("1.0", "1.1", "1.2")
CURRENT_VERSION = "1.3"


@dataclass
class Receipt:
    """Cryptographic receipt proving an AI output is real and unmodified.

    The canonical fields match the IETF AI workload attestation spec.
    Verify(receipt, public_key, log) = TRUE with only those three inputs, forever.
    """

    receipt_version: str = CURRENT_VERSION
    #   1.1 = injective length-prefixed preimage
    #   1.2 = 1.1 + signed_extensions commitment
    #   1.3 = 1.2 + receipt_id bound into the preimage (see canonical_message)
    model_weight_root: str = ""  # SHA-256 Merkle root of model weights
    model_root_type: str = "name_only"  # what model_weight_root actually is:
    #   "artifact_hash" = SHA-256 of a real weights file/dir (binds the weights)
    #   "api_attested"  = SHA-256 over the model id + provider metadata that the
    #                     CLOUD API RETURNED (gpt-4o-2024-08-06, system_fingerprint).
    #                     Proves input+output+claimed-model, NOT the weights - only
    #                     the provider can attest those. Honest cloud tier.
    #   "name_only"     = SHA-256 of a hand-typed model-name string only (proves the
    #                     CLAIM of that name; weakest - the user could type anything)
    input_commitment: str = ""  # SHA-256 of input prompt (may be hidden)
    output_hash: str = ""  # SHA-256 of model output
    timestamp_ms: int = 0  # Unix milliseconds
    log_sequence: int = 0  # uint64 monotonic counter in append-only log
    hw_evidence: List[Dict[str, Any]] = field(default_factory=list)  # [] in AetherProof; R1+ in Signet
    signature: str = ""  # Ed25519 (AetherProof) or Ed25519+ML-DSA-65 (Signet)
    log_anchor: str = ""  # "local://log/<log_sequence>" for open-source version
    receipt_id: str = ""  # Unique identifier ("ap_<random hex>")
    # SHA-256 of the signing public key, truncated - "which key signed this".
    # Absent in <=v1.2, so identifying the signer among M keys meant O(M) trial
    # verifications (measured: 38 attempts across 50 signers). Signed in v1.3.
    signing_key_id: str = ""
    # Namespaced signed extensions (e.g. agent-chain causal context, issue #1).
    # Each key is a namespace (e.g. "org.liminal.agent_chain/v0.1") mapping to a
    # JSON object. When non-empty, a SHA-256 commitment over the canonicalized
    # extensions is appended to the signing preimage and the receipt is v1.2.
    # When empty, the receipt is byte-for-byte a v1.1 receipt (backward compatible).
    signed_extensions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Default the timestamp, then derive receipt_id from it.

        Order matters: receipt_id is derived from timestamp_ms, so the timestamp
        must be defaulted FIRST. The reverse order (v0.2.2) produced
        "receipt_0" for every receipt built without an explicit timestamp -
        including every Receipt.for_api_call() - which then collided against the
        log's UNIQUE receipt_id constraint on the second append.
        """
        if not self.timestamp_ms:
            self.timestamp_ms = int(datetime.now().timestamp() * 1000)
        if not self.receipt_id:
            # timestamp alone is not unique at millisecond resolution, so mix in
            # entropy - two receipts issued in the same millisecond must differ.
            self.receipt_id = f"ap_{secrets.token_hex(4)}"
        # v1.2 only when extensions are present; otherwise stay v1.1 so existing
        # receipts and verifiers are unaffected.
        if self.signed_extensions and self.receipt_version == "1.1":
            self.receipt_version = "1.2"

    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary."""
        return asdict(self)

    def to_json(self, pretty: bool = False) -> str:
        """Export as JSON."""
        indent = 2 if pretty else None
        return json.dumps(self.to_dict(), indent=indent)

    def canonical_message(self) -> str:
        """Build the signing preimage for this receipt's version.

        Single source of truth - sign and verify must both call this, and
        byte-identical output is the only contract.

        INJECTIVE encoding: each field is length-prefixed as "<len>:<field>".
        A plain "|".join was non-injective - a "|" inside any field shifted the
        boundaries so two different receipts could share one preimage (and thus
        one signature). Length-prefixing makes the field boundaries unambiguous,
        so distinct field-tuples always produce distinct preimages.

        VERSION DISPATCH: v1.3 binds receipt_id and signing_key_id, which
        <=v1.2 left unsigned. The legacy builder is kept byte-exact so receipts
        already issued to third parties keep verifying - a fix that invalidated
        outstanding receipts would be worse than the defect.
        """
        fields = [
            self.receipt_version,
            self.model_weight_root,
            self.model_root_type,
            self.input_commitment,
            self.output_hash,
            str(self.timestamp_ms),
            str(self.log_sequence),
            self._canonical_hw_evidence(),
            self.log_anchor,
        ]
        if self.receipt_version not in LEGACY_VERSIONS:
            # v1.3+: receipt_id was rewritable on a standalone receipt file
            # without breaking the signature; signing_key_id makes signer
            # attribution O(1) instead of a brute-force search.
            fields.append(self.receipt_id)
            fields.append(self.signing_key_id)
        # v1.2: append the extensions commitment as one more length-prefixed
        # field. The injective encoding makes this unambiguous; a v1.1 receipt
        # never has this field, so the two can never collide.
        if self.signed_extensions:
            fields.append(self.signed_extensions_hash())
        return "".join(f"{len(f)}:{f}" for f in fields)

    def _canonical_hw_evidence(self) -> str:
        # canonical, key-sorted JSON so semantically-equal evidence (any key
        # order / whitespace) yields one preimage. [] for AetherProof; typed
        # objects for Signet R1+.
        return json.dumps(self.hw_evidence, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _canonicalize(obj: Any) -> bytes:
        # RFC 8785 JCS-equivalent for the string-valued extension objects this
        # format uses: sorted keys, no insignificant whitespace, UTF-8. (Full
        # RFC 8785 number formatting is not exercised because every extension
        # field is a string id / ref / enum, never a float.)
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def signed_extensions_hash(self) -> str:
        """Aggregated commitment over the signed extensions.

        NORMATIVE RULE: each extension yields a commitment
        `sha256(canon(namespace) || canon(body))`; those **commitments**are
        sorted lexicographically, concatenated, and hashed.

        The sort is over the resulting hashes, NOT over the namespace keys.
        Those two orders are not the same, and the previous implementation
        sorted namespaces while the documentation said commitments - so two
        implementations, each correctly following one reading, produced
        different signatures for the same receipt. Reported by Aleksey Safonov
        (safal207) in issue #1, 2026-06-24, and reproduced:

            namespaces 'ns.a3/v1' < 'ns.b3/v1'
            commitments d54ac416... > 99776f84...   (reversed)
            -> sorted-by-namespace  c55734d7...
               sorted-by-commitment cc60ffcc...

        A single extension is unaffected - one leaf sorts to itself - so
        receipts issued before this fix keep verifying unless they carried two
        or more extensions whose orders diverged.

        Scope note (also from issue #1): this aggregate provides multi-extension
        INTEGRITY, not standalone selective disclosure. Verifying one disclosed
        namespace requires either every other commitment or a Merkle inclusion
        proof. Disclosure is all-or-nothing at v1.2 by design; a
        domain-separated Merkle profile is deferred.
        """
        per = sorted(
            hashlib.sha256(
                self._canonicalize(ns) + self._canonicalize(body)
            ).hexdigest()
            for ns, body in self.signed_extensions.items()
        )
        agg = hashlib.sha256("".join(per).encode("utf-8")).hexdigest()
        return f"sha256:{agg}"

    def signing_bytes(self) -> bytes:
        return self.canonical_message().encode("utf-8")

    def to_compact_dict(self) -> Dict[str, Any]:
        """Export minimal representation (for binary serialization)."""
        return {
            "v": self.receipt_version,
            "mr": self.model_weight_root,
            "mrt": self.model_root_type,
            "ic": self.input_commitment,
            "oh": self.output_hash,
            "ts": self.timestamp_ms,
            "seq": self.log_sequence,
            "hwe": self.hw_evidence,
            "sig": self.signature,
            "la": self.log_anchor,
        }

    @staticmethod
    def api_attested_root(model_id: str, provider: str = "", **metadata: Any) -> str:
        """Build a model root from what a CLOUD API RETURNED - never from a
        hand-typed name.

        `model_id` is the resolved id the API echoed back (e.g.
        "gpt-4o-2024-08-06"), `provider` is "openai"/"anthropic"/"xai"/..., and
        metadata holds provider fields that pin the backend
        (system_fingerprint, response id, created). The order is fixed and the
        keys sorted so the same response always yields the same root.
        """
        # Length-prefixed, NOT "|".join. The join was non-injective in exactly
        # the way canonical_message() had already been fixed for: a caller could
        # smuggle "|system_fingerprint:fp_2" inside model_id and produce the same
        # root as an honest call that really carried that fingerprint, forging
        # the provider-metadata binding. Verified collision before the fix:
        #   root("m", sf="fp_2") == root("m|system_fingerprint:fp_2")
        parts = [f"api:{provider}", f"model:{model_id}"]
        for k in sorted(metadata):
            if metadata[k] is not None:
                parts.append(f"{k}:{metadata[k]}")
        preimage = "".join(f"{len(p)}:{p}" for p in parts)
        return hashlib.sha256(preimage.encode("utf-8")).hexdigest()

    @staticmethod
    def key_id(public_key) -> str:
        """Stable short identifier for a signing key: sha256 of its PEM, 16 hex.

        Lets a verifier pick the right public key in one lookup instead of
        trying every key it holds.
        """
        pem = public_key.export_public_pem()
        return hashlib.sha256(pem).hexdigest()[:16]

    @classmethod
    def for_api_call(
        cls,
        *,
        provider: str,
        model_id: str,
        prompt: str,
        output_text: str,
        response_metadata: Dict[str, Any] = None,
        log_sequence: int = 0,
        log_anchor: str = "",
    ) -> "Receipt":
        """Construct an honest cloud-API receipt (model_root_type='api_attested').

        The model identity comes from `model_id` - which the caller reads off the
        API RESPONSE (resp.model), not from a guess. Binds: input commitment,
        output hash, and the provider-reported model + metadata. Does NOT prove
        the weights ran (only the provider can attest that).
        """
        from .hash import hash_output

        meta = response_metadata or {}
        return cls(
            model_weight_root=cls.api_attested_root(model_id, provider, **meta),
            model_root_type="api_attested",
            input_commitment=hash_output(prompt),
            output_hash=hash_output(output_text),
            log_sequence=log_sequence,
            log_anchor=log_anchor,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Receipt":
        """Reconstruct from dictionary, coercing numeric fields to int.

        JSON or hand-built dicts may carry timestamp_ms / log_sequence as
        strings; the preimage str()-es them, so "1" and 1 would otherwise be
        treated as equal in one path and unequal in another. Coerce here so the
        in-memory type is canonical. Unknown keys are ignored rather than raising
        (forward-compatibility with newer receipt versions).
        """
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in data.items() if k in known}
        for num in ("timestamp_ms", "log_sequence"):
            if num in clean and clean[num] is not None:
                clean[num] = int(clean[num])
        return cls(**clean)

    @classmethod
    def from_json(cls, json_str: str) -> "Receipt":
        """Reconstruct from JSON."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def __repr__(self) -> str:
        """Human-readable summary."""
        return (
            f"Receipt(id={self.receipt_id}, "
            f"model_root={self.model_weight_root[:16]}..., "
            f"output_hash={self.output_hash[:16]}..., "
            f"signed={bool(self.signature)})"
        )
