"""Session receipts - sign a whole conversation, or any slice of one.

The problem this solves, measured on the shipped v0.2.2 code: proving that turn
457 of a 1000-turn session was really in that session required reading 457 log
rows and handing the auditor *every receipt in the session*. There was no
compact proof - `log_anchor` was the string "local://log/457".

Here each turn is a Merkle leaf. Sealing the session signs ONE root. Any single
turn then ships with a ~10-hash inclusion proof (ceil(log2(1000))), and checking
it reveals nothing about the other 999 turns - which is the selective-disclosure
property regulated buyers actually need.

    from aetherproof.core.session import Session

    s = Session(signer)
    s.record(prompt="what is 2+2?", output="4")        # turn 0
    s.record(prompt="and times 3?", output="12")       # turn 1
    ...
    seal  = s.seal()                  # sign the whole session
    seal  = s.seal(start=5, end=12)   # sign only turns 5..12
    proof = s.prove(7)                # compact proof for one turn

    Session.verify_turn(turn, proof, seal, public_key)   # offline, no server

Scope boundary: this is the FREE layer. It proves a turn belongs to a session
you sealed. It cannot prove you did not seal a *second*, edited session and show
that one instead - defeating that needs an independent witness publishing the
root, which is the transparency-log service (Signet). The split is deliberate:
everything provable on one machine is free and offline forever.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import json
import secrets

from .hash import sha256, merkle_leaf, merkle_node
from .receipt import Receipt
from .signer import Signer, Verifier

TURN_VERSION = "turn/v1"
SEAL_VERSION = "session-seal/v1"


# ── Merkle tree with inclusion proofs ────────────────────────────────────────
# Same construction as hash.compute_merkle_root: RFC 6962 domain separation,
# odd node promoted rather than duplicated. The proof format must match that
# shape exactly or verification silently diverges, so both live on one builder.

def build_levels(leaf_hashes: List[str]) -> List[List[str]]:
    """Bottom-up tree. levels[0] is the tagged leaves, levels[-1] is [root]."""
    if not leaf_hashes:
        return [[]]
    level = [merkle_leaf(h) for h in leaf_hashes]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(merkle_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote, never duplicate
        levels.append(nxt)
        level = nxt
    return levels


def merkle_root(leaf_hashes: List[str]) -> str:
    if not leaf_hashes:
        return ""
    return build_levels(leaf_hashes)[-1][0]


def inclusion_proof(leaf_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    """Sibling path for `index` as [(side, hash)], side in {"L","R"}.

    A promoted node contributes no sibling at that level, so proofs are not all
    the same length - that is expected, not a bug.
    """
    if not 0 <= index < len(leaf_hashes):
        raise IndexError(f"turn {index} outside 0..{len(leaf_hashes) - 1}")
    levels = build_levels(leaf_hashes)
    proof: List[Tuple[str, str]] = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                proof.append(("R", level[idx + 1]))
        else:
            proof.append(("L", level[idx - 1]))
        idx //= 2
    return proof


def verify_inclusion(leaf_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    """Recompute the root from one leaf plus its sibling path."""
    h = merkle_leaf(leaf_hash)
    for side, sibling in proof:
        if side == "L":
            h = merkle_node(sibling, h)
        elif side == "R":
            h = merkle_node(h, sibling)
        else:
            return False
    return h == root


# ── Turn ─────────────────────────────────────────────────────────────────────

@dataclass
class Turn:
    """One question/answer exchange. Hashed, never stored in the seal."""

    index: int = 0
    prompt_hash: str = ""
    output_hash: str = ""
    model_id: str = ""
    model_root_type: str = "name_only"
    timestamp_ms: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp_ms:
            self.timestamp_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    def leaf_hash(self) -> str:
        """Injective, length-prefixed commitment to this turn.

        Same encoding discipline as Receipt.canonical_message - a delimiter
        inside model_id must not be able to shift field boundaries.
        """
        parts = [
            TURN_VERSION,
            str(self.index),
            self.prompt_hash,
            self.output_hash,
            self.model_id,
            self.model_root_type,
            str(self.timestamp_ms),
            json.dumps(self.meta, sort_keys=True, separators=(",", ":")),
        ]
        return sha256("".join(f"{len(p)}:{p}" for p in parts))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Turn":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in d.items() if k in known}
        for n in ("index", "timestamp_ms"):
            if n in clean and clean[n] is not None:
                clean[n] = int(clean[n])
        return cls(**clean)


# ── Seal ─────────────────────────────────────────────────────────────────────

@dataclass
class SessionSeal:
    """A signed commitment to a contiguous range of turns."""

    seal_version: str = SEAL_VERSION
    session_id: str = ""
    merkle_root: str = ""
    start: int = 0          # inclusive
    end: int = 0            # inclusive
    turn_count: int = 0
    sealed_at_ms: int = 0
    signing_key_id: str = ""
    signature: str = ""

    def canonical_message(self) -> str:
        parts = [
            self.seal_version,
            self.session_id,
            self.merkle_root,
            str(self.start),
            str(self.end),
            str(self.turn_count),
            str(self.sealed_at_ms),
            self.signing_key_id,
        ]
        return "".join(f"{len(p)}:{p}" for p in parts)

    def signing_bytes(self) -> bytes:
        return self.canonical_message().encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, pretty: bool = False) -> str:
        return json.dumps(self.to_dict(), indent=2 if pretty else None)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SessionSeal":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in d.items() if k in known}
        for n in ("start", "end", "turn_count", "sealed_at_ms"):
            if n in clean and clean[n] is not None:
                clean[n] = int(clean[n])
        return cls(**clean)

    @classmethod
    def from_json(cls, s: str) -> "SessionSeal":
        return cls.from_dict(json.loads(s))

    def covers(self, index: int) -> bool:
        return self.start <= index <= self.end


@dataclass
class TurnProof:
    """A single turn plus the sibling path binding it to a seal."""

    turn: Turn
    proof: List[Tuple[str, str]]
    session_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "turn": self.turn.to_dict(),
            "proof": [list(p) for p in self.proof],
            "session_id": self.session_id,
        }

    def to_json(self, pretty: bool = False) -> str:
        return json.dumps(self.to_dict(), indent=2 if pretty else None)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TurnProof":
        return cls(turn=Turn.from_dict(d["turn"]),
                   proof=[tuple(p) for p in d.get("proof", [])],
                   session_id=d.get("session_id", ""))

    @classmethod
    def from_json(cls, s: str) -> "TurnProof":
        return cls.from_dict(json.loads(s))


# ── Session ──────────────────────────────────────────────────────────────────

class Session:
    """Accumulate turns, then sign the whole session or any slice of it."""

    def __init__(self, signer: Optional[Signer] = None, session_id: str = "",
                 model_id: str = "", model_root_type: str = "name_only"):
        self.signer = signer
        self.session_id = session_id or f"s_{secrets.token_hex(8)}"
        self.model_id = model_id
        self.model_root_type = model_root_type
        self.turns: List[Turn] = []

    def __len__(self) -> int:
        return len(self.turns)

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def record(self, prompt: str = "", output: str = "", *,
               prompt_hash: str = "", output_hash: str = "",
               model_id: str = "", model_root_type: str = "",
               **meta: Any) -> Turn:
        """Append a turn. Pass text (hashed here) or pre-computed hashes.

        Accepting hashes matters for the lazy path: a caller streaming a huge
        output, or one that must not retain plaintext, can hash it themselves.
        """
        turn = Turn(
            index=len(self.turns),
            prompt_hash=prompt_hash or (sha256(prompt) if prompt else ""),
            output_hash=output_hash or (sha256(output) if output else ""),
            model_id=model_id or self.model_id,
            model_root_type=model_root_type or self.model_root_type,
            meta=meta,
        )
        self.turns.append(turn)
        return turn

    def _slice(self, start: Optional[int], end: Optional[int]) -> Tuple[int, int]:
        if not self.turns:
            raise ValueError("nothing to seal: no turns recorded")
        s = 0 if start is None else start
        e = len(self.turns) - 1 if end is None else end
        if s < 0 or e >= len(self.turns) or s > e:
            raise ValueError(
                f"range {s}..{e} outside 0..{len(self.turns) - 1}")
        return s, e

    def leaves(self, start: Optional[int] = None, end: Optional[int] = None) -> List[str]:
        s, e = self._slice(start, end)
        return [t.leaf_hash() for t in self.turns[s:e + 1]]

    def root(self, start: Optional[int] = None, end: Optional[int] = None) -> str:
        return merkle_root(self.leaves(start, end))

    def seal(self, start: Optional[int] = None, end: Optional[int] = None,
             signer: Optional[Signer] = None) -> SessionSeal:
        """Sign a commitment to turns start..end (inclusive; default: all).

        `seal()`                whole session
        `seal(start=5, end=12)` a slice
        `seal(start=7, end=7)`  a single turn
        """
        sgn = signer or self.signer
        if sgn is None:
            raise ValueError("a Signer is required to seal (pass one to Session or seal)")
        s, e = self._slice(start, end)
        seal = SessionSeal(
            session_id=self.session_id,
            merkle_root=merkle_root(self.leaves(s, e)),
            start=s,
            end=e,
            turn_count=e - s + 1,
            sealed_at_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
            signing_key_id=Receipt.key_id(sgn.get_public_key()),
        )
        seal.signature = sgn.sign(seal.signing_bytes())
        return seal

    def prove(self, index: int, start: Optional[int] = None,
              end: Optional[int] = None) -> TurnProof:
        """Compact proof that turn `index` sits inside the sealed range."""
        s, e = self._slice(start, end)
        if not s <= index <= e:
            raise IndexError(f"turn {index} outside sealed range {s}..{e}")
        leaves = self.leaves(s, e)
        return TurnProof(turn=self.turns[index],
                         proof=inclusion_proof(leaves, index - s),
                         session_id=self.session_id)

    # ── verification (static: needs no Session instance) ─────────────────────

    @staticmethod
    def verify_seal(seal: SessionSeal, public_key: Verifier) -> bool:
        """Is this seal authentically signed? Offline, no log, no server."""
        if not seal.merkle_root or not seal.signature:
            return False
        return public_key.verify(seal.signing_bytes(), seal.signature)

    @staticmethod
    def verify_turn(turn_proof: TurnProof, seal: SessionSeal,
                    public_key: Verifier) -> bool:
        """Full check: seal is authentic AND this turn is inside it.

        Costs len(proof) hashes - ~10 for a 1000-turn session - and needs none
        of the other turns.
        """
        if not Session.verify_seal(seal, public_key):
            return False
        if turn_proof.session_id and turn_proof.session_id != seal.session_id:
            return False
        if not seal.covers(turn_proof.turn.index):
            return False
        return verify_inclusion(turn_proof.turn.leaf_hash(),
                                turn_proof.proof, seal.merkle_root)

    @staticmethod
    def verify_content(turn_proof: TurnProof, prompt: str = None,
                       output: str = None) -> bool:
        """Do the original texts still hash to what the turn committed to?"""
        t = turn_proof.turn
        if prompt is not None and sha256(prompt) != t.prompt_hash:
            return False
        if output is not None and sha256(output) != t.output_hash:
            return False
        return True
