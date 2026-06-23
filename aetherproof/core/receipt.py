"""Receipt dataclass and canonical field definitions."""

from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any
import json
from datetime import datetime


@dataclass
class Receipt:
    """Cryptographic receipt proving an AI output is real and unmodified.

    The canonical fields match the IETF AI workload attestation spec.
    Verify(receipt, public_key, log) = TRUE with only those three inputs, forever.
    """

    receipt_version: str = "1.1"  # 1.1 = injective length-prefixed preimage
    model_weight_root: str = ""  # SHA-256 Merkle root of model weights
    model_root_type: str = "name_only"  # what model_weight_root actually is:
    #   "artifact_hash" = SHA-256 of a real weights file/dir (binds to the weights)
    #   "name_only"     = SHA-256 of a model-name string only (proves the CLAIM of
    #                     that name at that time; does NOT prove the weights)
    input_commitment: str = ""  # SHA-256 of input prompt (may be hidden)
    output_hash: str = ""  # SHA-256 of model output
    timestamp_ms: int = 0  # Unix milliseconds
    log_sequence: int = 0  # uint64 monotonic counter in append-only log
    hw_evidence: List[Dict[str, Any]] = field(default_factory=list)  # [] in AetherProof; R1+ in Signet
    signature: str = ""  # Ed25519 (AetherProof) or Ed25519+ML-DSA-65 (Signet)
    log_anchor: str = ""  # "local://log/<log_sequence>" for open-source version
    receipt_id: str = ""  # Unique identifier (timestamp-based)
    # Namespaced signed extensions (e.g. agent-chain causal context, issue #1).
    # Each key is a namespace (e.g. "org.liminal.agent_chain/v0.1") mapping to a
    # JSON object. When non-empty, a SHA-256 commitment over the canonicalized
    # extensions is appended to the signing preimage and the receipt is v1.2.
    # When empty, the receipt is byte-for-byte a v1.1 receipt (backward compatible).
    signed_extensions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Set receipt_id if not provided."""
        if not self.receipt_id:
            self.receipt_id = f"receipt_{self.timestamp_ms}"
        if not self.timestamp_ms:
            self.timestamp_ms = int(datetime.now().timestamp() * 1000)
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
        # signing preimage — single source of truth; sign and verify must
        # both use this. byte-identical output is the only contract.
        #
        # INJECTIVE encoding: each field is length-prefixed as "<len>:<field>".
        # A plain "|".join was non-injective — a "|" inside any field shifted the
        # boundaries so two different receipts could share one preimage (and thus
        # one signature). Length-prefixing makes the field boundaries unambiguous,
        # so distinct field-tuples always produce distinct preimages.
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

        Per-extension commitments (sha256 of each namespace's canonical bytes),
        sorted, then hashed together. Per-extension (not whole-map) so a holder
        can disclose or omit one namespace without breaking the others — the same
        selective-disclosure property the base receipt respects. With a single
        extension the two collapse to identical bytes, so this is forward-safe.
        """
        import hashlib

        per = []
        for ns in sorted(self.signed_extensions):
            body = self._canonicalize(self.signed_extensions[ns])
            leaf = hashlib.sha256(self._canonicalize(ns) + body).hexdigest()
            per.append(leaf)
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
