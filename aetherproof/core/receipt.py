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

    receipt_version: str = "1.0"
    model_weight_root: str = ""  # SHA-256 Merkle root of model weights
    input_commitment: str = ""  # SHA-256 of input prompt (may be hidden)
    output_hash: str = ""  # SHA-256 of model output
    timestamp_ms: int = 0  # Unix milliseconds
    log_sequence: int = 0  # uint64 monotonic counter in append-only log
    hw_evidence: List[Dict[str, Any]] = field(default_factory=list)  # [] in AetherProof; R1+ in Signet
    signature: str = ""  # Ed25519 (AetherProof) or Ed25519+ML-DSA-65 (Signet)
    log_anchor: str = ""  # "local://log/<log_sequence>" for open-source version
    receipt_id: str = ""  # Unique identifier (timestamp-based)

    def __post_init__(self):
        """Set receipt_id if not provided."""
        if not self.receipt_id:
            self.receipt_id = f"receipt_{self.timestamp_ms}"
        if not self.timestamp_ms:
            self.timestamp_ms = int(datetime.now().timestamp() * 1000)

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
        return "|".join([
            self.receipt_version,
            self.model_weight_root,
            self.input_commitment,
            self.output_hash,
            str(self.timestamp_ms),
            str(self.log_sequence),
            str(self.hw_evidence),
            self.log_anchor,
        ])

    def signing_bytes(self) -> bytes:
        return self.canonical_message().encode("utf-8")

    def to_compact_dict(self) -> Dict[str, Any]:
        """Export minimal representation (for binary serialization)."""
        return {
            "v": self.receipt_version,
            "mr": self.model_weight_root,
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
        """Reconstruct from dictionary."""
        return cls(**data)

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
