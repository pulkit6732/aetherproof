"""Session receipts - Merkle trees, range sealing, inclusion proofs.

Covers core/session.py, which closes D10: proving that turn K belonged to a
session used to require reading every prior log row and handing the auditor the
whole session. A turn now ships with a ~log2(N) sibling path instead.

Properties that must hold:
  - a proof verifies against the seal, and nothing else does
  - proving one turn reveals nothing about, and needs nothing from, the others
  - every tamper path (turn, path, seal, key, range) rejects
  - the tree inherits the RFC 6962 fixes: no odd-leaf duplication, domain separation
"""

import json
import math

import pytest

from aetherproof.core.hash import sha256, merkle_leaf, merkle_node
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.session import (
    Session,
    SessionSeal,
    Turn,
    TurnProof,
    build_levels,
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)


@pytest.fixture
def signer():
    return Signer.generate()


@pytest.fixture
def pub(signer):
    return signer.get_public_key()


def make_session(signer, n=16):
    s = Session(signer, model_id="claude-opus-5", model_root_type="api_attested")
    for i in range(n):
        s.record(prompt=f"q{i}", output=f"a{i}")
    return s


# ── tree construction ────────────────────────────────────────────────────────

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 33, 100])
def test_every_leaf_proves_against_the_root(n):
    """The proof format must match the tree shape at every size.

    Odd levels promote rather than duplicate, so proofs are not all the same
    length - an off-by-one in the promotion path would only show up at some n.
    """
    leaves = [sha256(f"leaf{i}") for i in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        assert verify_inclusion(leaves[i], inclusion_proof(leaves, i), root), f"n={n} i={i}"


def test_proof_length_is_logarithmic():
    leaves = [sha256(f"l{i}") for i in range(1000)]
    proof = inclusion_proof(leaves, 457)
    assert len(proof) <= math.ceil(math.log2(1000))


def test_wrong_leaf_does_not_verify():
    leaves = [sha256(f"l{i}") for i in range(8)]
    root = merkle_root(leaves)
    assert verify_inclusion(sha256("not-in-tree"), inclusion_proof(leaves, 3), root) is False


def test_proof_for_one_index_does_not_verify_another():
    leaves = [sha256(f"l{i}") for i in range(8)]
    root = merkle_root(leaves)
    assert verify_inclusion(leaves[4], inclusion_proof(leaves, 3), root) is False


def test_tree_inherits_no_odd_leaf_duplication():
    a, b, c = sha256("a"), sha256("b"), sha256("c")
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])


def test_tree_inherits_domain_separation():
    a, b = sha256("a"), sha256("b")
    internal = merkle_node(merkle_leaf(a), merkle_leaf(b))
    assert merkle_root([a, b]) != merkle_root([internal])


def test_empty_tree():
    assert merkle_root([]) == ""
    assert build_levels([]) == [[]]


def test_proof_index_out_of_range():
    leaves = [sha256("a"), sha256("b")]
    with pytest.raises(IndexError):
        inclusion_proof(leaves, 5)


# ── turn leaves ──────────────────────────────────────────────────────────────

def test_turn_leaf_is_injective_over_delimiters():
    """A delimiter inside model_id must not shift field boundaries."""
    a = Turn(index=1, prompt_hash="p", output_hash="o", model_id="m",
             model_root_type="name_only", timestamp_ms=1)
    b = Turn(index=1, prompt_hash="p", output_hash="o", model_id="m1:name_only",
             model_root_type="", timestamp_ms=1)
    assert a.leaf_hash() != b.leaf_hash()


def test_turn_index_is_bound():
    a = Turn(index=1, prompt_hash="p", output_hash="o", timestamp_ms=1)
    b = Turn(index=2, prompt_hash="p", output_hash="o", timestamp_ms=1)
    assert a.leaf_hash() != b.leaf_hash()


def test_turn_meta_is_bound_and_key_order_independent():
    a = Turn(index=0, timestamp_ms=1, meta={"x": "1", "y": "2"})
    b = Turn(index=0, timestamp_ms=1, meta={"y": "2", "x": "1"})
    c = Turn(index=0, timestamp_ms=1, meta={"x": "9", "y": "2"})
    assert a.leaf_hash() == b.leaf_hash()
    assert a.leaf_hash() != c.leaf_hash()


def test_turn_round_trips(signer):
    t = make_session(signer, 4).turns[2]
    assert Turn.from_dict(t.to_dict()).leaf_hash() == t.leaf_hash()


# ── sealing ──────────────────────────────────────────────────────────────────

def test_seal_whole_session_verifies(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    assert Session.verify_seal(seal, pub) is True
    assert seal.start == 0 and seal.end == len(s) - 1
    assert seal.turn_count == len(s)


def test_seal_names_its_signing_key(signer, pub):
    seal = make_session(signer).seal()
    assert seal.signing_key_id == Receipt.key_id(pub)


def test_seal_is_one_signature_regardless_of_turn_count(signer):
    small = make_session(signer, 4).seal()
    large = make_session(signer, 512).seal()
    assert len(small.to_json()) == pytest.approx(len(large.to_json()), abs=40)


@pytest.mark.parametrize("start,end", [(0, 0), (5, 12), (3, 3), (0, 15)])
def test_range_seal_covers_only_its_range(signer, pub, start, end):
    s = make_session(signer)
    seal = s.seal(start=start, end=end)
    assert Session.verify_seal(seal, pub) is True
    assert seal.turn_count == end - start + 1
    for i in range(len(s)):
        assert seal.covers(i) is (start <= i <= end)


def test_disjoint_ranges_have_different_roots(signer):
    s = make_session(signer)
    assert s.seal(start=0, end=7).merkle_root != s.seal(start=8, end=15).merkle_root


def test_seal_requires_a_signer():
    s = Session()
    s.record(prompt="p", output="o")
    with pytest.raises(ValueError):
        s.seal()


def test_seal_rejects_empty_session(signer):
    with pytest.raises(ValueError):
        Session(signer).seal()


@pytest.mark.parametrize("start,end", [(-1, 3), (0, 99), (5, 2)])
def test_seal_rejects_bad_range(signer, start, end):
    s = make_session(signer)
    with pytest.raises(ValueError):
        s.seal(start=start, end=end)


def test_seal_round_trips_through_json(signer, pub):
    seal = make_session(signer).seal()
    assert Session.verify_seal(SessionSeal.from_json(seal.to_json()), pub) is True


# ── proving a single turn ────────────────────────────────────────────────────

def test_prove_and_verify_every_turn(signer, pub):
    s = make_session(signer, 33)
    seal = s.seal()
    for i in range(len(s)):
        assert Session.verify_turn(s.prove(i), seal, pub) is True, f"turn {i}"


def test_verify_turn_needs_no_other_turns(signer, pub):
    """The auditor gets one turn + its path + the seal, and nothing else."""
    s = make_session(signer, 64)
    seal = s.seal()
    wire = s.prove(37).to_json()

    revived = TurnProof.from_json(wire)          # a fresh party, no Session object
    assert Session.verify_turn(revived, seal, pub) is True

    payload = json.loads(wire)
    assert set(payload) == {"turn", "proof", "session_id"}
    assert len(payload["proof"]) <= math.ceil(math.log2(64))


def test_proof_carries_no_plaintext(signer, pub):
    """Only hashes cross the wire - the prompt and output never do."""
    s = Session(signer)
    s.record(prompt="PATIENT NAME REDACTED", output="SECRET DIAGNOSIS")
    wire = s.prove(0, start=0, end=0).to_json()
    assert "PATIENT" not in wire and "SECRET" not in wire


def test_prove_within_a_range(signer, pub):
    s = make_session(signer)
    seal = s.seal(start=5, end=12)
    for i in range(5, 13):
        assert Session.verify_turn(s.prove(i, start=5, end=12), seal, pub) is True


def test_prove_outside_the_range_raises(signer):
    s = make_session(signer)
    with pytest.raises(IndexError):
        s.prove(2, start=5, end=12)


# ── tamper and forgery ───────────────────────────────────────────────────────

def test_edited_output_rejects(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    p = s.prove(7)
    p.turn.output_hash = "f" * 64
    assert Session.verify_turn(p, seal, pub) is False


def test_edited_turn_index_rejects(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    p = s.prove(7)
    p.turn.index = 8
    assert Session.verify_turn(p, seal, pub) is False


def test_tampered_sibling_path_rejects(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    p = s.prove(7)
    p.proof = [("L", "0" * 64)] + p.proof[1:]
    assert Session.verify_turn(p, seal, pub) is False


def test_flipped_sibling_side_rejects(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    p = s.prove(7)
    side, h = p.proof[0]
    p.proof[0] = ("L" if side == "R" else "R", h)
    assert Session.verify_turn(p, seal, pub) is False


def test_truncated_proof_rejects(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    p = s.prove(7)
    p.proof = p.proof[:-1]
    assert Session.verify_turn(p, seal, pub) is False


def test_malformed_side_marker_rejects(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    p = s.prove(7)
    p.proof[0] = ("X", p.proof[0][1])
    assert Session.verify_turn(p, seal, pub) is False


def test_edited_seal_root_rejects(signer, pub):
    s = make_session(signer)
    seal = s.seal()
    seal.merkle_root = "0" * 64
    assert Session.verify_seal(seal, pub) is False


@pytest.mark.parametrize("field,value", [
    ("session_id", "s_forged"), ("start", 3), ("end", 4),
    ("turn_count", 999), ("sealed_at_ms", 1), ("signing_key_id", "dead" * 4),
])
def test_every_seal_field_is_signed(signer, pub, field, value):
    seal = make_session(signer).seal()
    setattr(seal, field, value)
    assert Session.verify_seal(seal, pub) is False


def test_wrong_public_key_rejects(signer):
    s = make_session(signer)
    seal = s.seal()
    assert Session.verify_turn(s.prove(7), seal, Signer.generate().get_public_key()) is False


def test_unsigned_seal_rejects(signer, pub):
    seal = make_session(signer).seal()
    seal.signature = ""
    assert Session.verify_seal(seal, pub) is False


def test_turn_from_another_session_rejects(signer, pub):
    a, b = make_session(signer), make_session(signer)
    assert Session.verify_turn(a.prove(7), b.seal(), pub) is False


def test_turn_outside_sealed_range_rejects(signer, pub):
    s = make_session(signer, 32)
    assert Session.verify_turn(s.prove(20), s.seal(start=0, end=10), pub) is False


# ── content binding ──────────────────────────────────────────────────────────

def test_verify_content_matches_and_detects_edits(signer):
    s = Session(signer)
    s.record(prompt="what is 2+2?", output="4")
    p = s.prove(0, start=0, end=0)
    assert Session.verify_content(p, prompt="what is 2+2?", output="4") is True
    assert Session.verify_content(p, output="5") is False
    assert Session.verify_content(p, prompt="different") is False


def test_record_accepts_precomputed_hashes(signer, pub):
    """The streaming / no-plaintext-retained path."""
    s = Session(signer)
    s.record(prompt_hash=sha256("big prompt"), output_hash=sha256("big output"))
    seal = s.seal()
    assert Session.verify_turn(s.prove(0), seal, pub) is True
    assert Session.verify_content(s.prove(0), output="big output") is True
