"""The Python Merkle implementation against the published vectors (spec/merkle_vectors.txt).
The Rust core checks the same file in `cargo test`, so the two cannot drift silently even
when the optional native extension is not built."""

from pathlib import Path

from aetherproof.core.hash import compute_merkle_root, merkle_leaf, merkle_node
from aetherproof.core.session import inclusion_proof, verify_inclusion

VECTORS = Path(__file__).resolve().parents[1] / "spec" / "merkle_vectors.txt"


def rows(kind):
    for line in VECTORS.read_text(encoding="utf-8").splitlines():
        if line.startswith(kind + " "):
            yield line.split(" ")[1:]


def leaves(field):
    return [] if field == "-" else field.split(",")


def test_vector_file_covers_every_kind():
    counts = {k: len(list(rows(k))) for k in ("leaf", "node", "root", "proof")}
    assert counts["leaf"] >= 3 and counts["node"] >= 1 and counts["root"] >= 10 and counts["proof"] >= 20


def test_leaf_and_node_vectors():
    for inp, out in rows("leaf"):
        assert merkle_leaf(inp) == out
    for left, right, out in rows("node"):
        assert merkle_node(left, right) == out


def test_root_vectors_including_empty_and_odd_sizes():
    for ls, root in rows("root"):
        assert compute_merkle_root(leaves(ls)) == ("" if root == "-" else root)


def test_proof_vectors_match_and_verify():
    for ls, idx, proof in rows("proof"):
        lv, i = leaves(ls), int(idx)
        want = [] if proof == "-" else [tuple(step.split(":")) for step in proof.split(";")]
        assert inclusion_proof(lv, i) == want
        assert verify_inclusion(lv[i], want, compute_merkle_root(lv))
