//! Python bindings for the AetherProof Rust core.
//!
//! Author: Pulkit Kr Srivastava <pulkitsrivastavae@gmail.com>
//!
//! # Design rule: additive, never substitutive
//!
//! Importing this module changes nothing about how the pure-Python package
//! behaves. `aetherproof` does not import it, does not require it, and works
//! identically whether or not it is present. The extension exists so callers who
//! want the faster path can opt in, and so the two implementations can be checked
//! against each other in tests.
//!
//! Every function here is a thin wrapper over `aetherproof_core`. There is no
//! second implementation of any algorithm in this file — that is the whole point.
//! A binding that reimplements logic is a second place for the signing preimage to
//! drift, which is the defect class this project already fixed once.

use aetherproof_core as core;
use pyo3::exceptions::{PyIndexError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ── Merkle ───────────────────────────────────────────────────────────────────

/// Hash a leaf under the leaf domain tag (`0x00`).
#[pyfunction]
fn merkle_leaf(leaf_hash: &str) -> String {
    core::merkle::merkle_leaf(leaf_hash)
}

/// Hash an internal node under the node domain tag (`0x01`).
#[pyfunction]
fn merkle_node(left: &str, right: &str) -> String {
    core::merkle::merkle_node(left, right)
}

/// Merkle root over leaf hashes. Empty input yields an empty string.
#[pyfunction]
fn merkle_root(leaf_hashes: Vec<String>) -> String {
    core::merkle::merkle_root(&leaf_hashes)
}

/// Sibling path for `index`, as a list of `(side, hash)` where side is "L" or "R".
///
/// Matches the tuple shape returned by `aetherproof.core.session.inclusion_proof`.
#[pyfunction]
fn inclusion_proof(leaf_hashes: Vec<String>, index: usize) -> PyResult<Vec<(String, String)>> {
    core::merkle::inclusion_proof(&leaf_hashes, index)
        .map(|steps| {
            steps
                .into_iter()
                .map(|s| (s.side.as_str().to_string(), s.hash))
                .collect()
        })
        .ok_or_else(|| {
            PyIndexError::new_err(format!(
                "turn {index} outside 0..{}",
                leaf_hashes.len().saturating_sub(1)
            ))
        })
}

/// Recompute the root from one leaf plus its sibling path and compare.
///
/// An unrecognised side value returns `False` rather than raising, matching the
/// Python implementation.
#[pyfunction]
fn verify_inclusion(leaf_hash: &str, proof: Vec<(String, String)>, root: &str) -> bool {
    let mut steps = Vec::with_capacity(proof.len());
    for (side, hash) in proof {
        match core::merkle::Side::parse(&side) {
            Some(s) => steps.push(core::merkle::ProofStep { side: s, hash }),
            None => return false,
        }
    }
    core::merkle::verify_inclusion(leaf_hash, &steps, root)
}

// ── Receipts ─────────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash, as used for the receipt's `binary_hash` field.
#[pyfunction]
fn fnv1a(data: &[u8]) -> u64 {
    core::fnv1a(data)
}

/// Generate and sign a 128-byte receipt. Returns the serialised bytes.
///
/// `signing_key` must be the 32-byte Ed25519 seed.
#[pyfunction]
fn generate_receipt<'p>(
    py: Python<'p>,
    pid: u32,
    binary: &[u8],
    memory_hash: u64,
    syscall_count: u32,
    signing_key: &[u8],
) -> PyResult<Bound<'p, PyBytes>> {
    let seed: [u8; 32] = signing_key
        .try_into()
        .map_err(|_| PyValueError::new_err("signing_key must be exactly 32 bytes"))?;
    let sk = core::SigningKey::from_bytes(&seed);
    let r = core::generate(pid, binary, memory_hash, syscall_count, &sk);
    Ok(PyBytes::new(py, &core::to_bytes(&r)))
}

/// Verify a 128-byte receipt against a 32-byte Ed25519 public key.
#[pyfunction]
fn verify_receipt(data: &[u8], public_key: &[u8]) -> PyResult<bool> {
    let receipt: &[u8; core::RECEIPT_SIZE] = match data.try_into() {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| PyValueError::new_err("public_key must be exactly 32 bytes"))?;
    let vk = match core::VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    Ok(core::verify(receipt, &vk))
}

/// Size of a core receipt in bytes.
#[pyfunction]
fn receipt_size() -> usize {
    core::RECEIPT_SIZE
}

// ── Post-quantum ─────────────────────────────────────────────────────────────

/// Generate an ML-DSA-65 keypair. Returns `(public_bytes, private_bytes)`.
#[pyfunction]
fn pq_keygen(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    use core::pq::fips204::traits::SerDes;
    let kp = core::pq::PqKeypair::generate()
        .map_err(|e| PyValueError::new_err(format!("ML-DSA keygen failed: {e:?}")))?;
    let pk = kp.public.clone().into_bytes();
    let sk = kp.private.clone().into_bytes();
    Ok((
        PyBytes::new(py, &pk).unbind(),
        PyBytes::new(py, &sk).unbind(),
    ))
}

/// Attach an ML-DSA-65 signature to a 128-byte core receipt.
#[pyfunction]
fn pq_attach<'p>(
    py: Python<'p>,
    core_receipt: &[u8],
    private_key: &[u8],
) -> PyResult<Bound<'p, PyBytes>> {
    use core::pq::fips204::ml_dsa_65;
    use core::pq::fips204::traits::SerDes;
    let sk_arr: [u8; ml_dsa_65::SK_LEN] = private_key
        .try_into()
        .map_err(|_| PyValueError::new_err("private_key is not an ML-DSA-65 private key"))?;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
        .map_err(|e| PyValueError::new_err(format!("bad ML-DSA private key: {e:?}")))?;
    let out = core::pq::attach(core_receipt, &sk)
        .map_err(|e| PyValueError::new_err(format!("attach failed: {e:?}")))?;
    Ok(PyBytes::new(py, &out))
}

/// Verify only the ML-DSA-65 signature on a hybrid receipt.
#[pyfunction]
fn pq_verify(data: &[u8], public_key: &[u8]) -> PyResult<bool> {
    use core::pq::fips204::ml_dsa_65;
    use core::pq::fips204::traits::SerDes;
    let pk_arr: [u8; ml_dsa_65::PK_LEN] = match public_key.try_into() {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };
    let pk = match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    Ok(core::pq::verify_pq(data, &pk))
}

/// True if `data` carries a post-quantum trailer.
#[pyfunction]
fn pq_has_trailer(data: &[u8]) -> bool {
    core::pq::has_trailer(data)
}

// ── Security layer ───────────────────────────────────────────────────────────

/// An Ed25519 signing key held inside Rust and wiped when released.
///
/// The secret never crosses into Python. `generate()` produces it here, signing
/// happens here, and only public keys and signatures come back out. A Python
/// `bytes` object holding a key cannot be wiped — it is immutable, and garbage
/// collection does not overwrite it — so a key that round-trips through Python
/// stays readable in the heap long after its last use.
#[pyclass(name = "SecureSigner", unsendable)]
struct PySecureSigner {
    inner: core::secure::SecureSigner,
}

#[pymethods]
impl PySecureSigner {
    /// Generate a fresh key from operating-system entropy.
    #[new]
    fn new() -> PyResult<Self> {
        core::secure::SecureSigner::generate()
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// Adopt an existing 32-byte seed.
    ///
    /// The caller's copy cannot be wiped by this object. Prefer the constructor
    /// where the key does not already exist.
    #[staticmethod]
    fn from_seed(seed: &[u8]) -> PyResult<Self> {
        core::secure::SecureSigner::from_seed(seed)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// True while the key is still usable.
    #[getter]
    fn is_live(&self) -> bool {
        self.inner.is_live()
    }

    /// The 32-byte Ed25519 public key.
    fn public_key<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        self.inner
            .public_key()
            .map(|k| PyBytes::new(py, &k))
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// Sign a message, returning the 64-byte signature.
    fn sign<'p>(&self, py: Python<'p>, message: &[u8]) -> PyResult<Bound<'p, PyBytes>> {
        self.inner
            .sign(message)
            .map(|s| PyBytes::new(py, &s))
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// Produce a signed 128-byte receipt without the key leaving Rust.
    fn sign_receipt<'p>(
        &self,
        py: Python<'p>,
        pid: u32,
        binary: &[u8],
        memory_hash: u64,
        syscall_count: u32,
    ) -> PyResult<Bound<'p, PyBytes>> {
        self.inner
            .sign_receipt(pid, binary, memory_hash, syscall_count)
            .map(|r| PyBytes::new(py, &r))
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// Overwrite the key now rather than waiting for collection.
    fn destroy(&mut self) {
        self.inner.destroy();
    }

    /// Usable as a context manager so the key is wiped on block exit.
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _t: Option<Bound<'_, PyAny>>,
        _v: Option<Bound<'_, PyAny>>,
        _b: Option<Bound<'_, PyAny>>,
    ) -> bool {
        self.inner.destroy();
        false
    }

    /// No key material, deliberately. A repr that shows a secret ends up in logs.
    fn __repr__(&self) -> String {
        format!(
            "<SecureSigner {}>",
            if self.inner.is_live() {
                "live"
            } else {
                "destroyed"
            }
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// A verifier carrying only public material, which fails closed.
#[pyclass(name = "SecureVerifier")]
#[derive(Clone)]
struct PySecureVerifier {
    inner: core::secure::SecureVerifier,
}

#[pymethods]
impl PySecureVerifier {
    /// Build from a 32-byte Ed25519 public key.
    ///
    /// Malformed key material is rejected here rather than producing an object
    /// that accepts everything at verification time.
    #[new]
    fn new(public_key: &[u8]) -> PyResult<Self> {
        core::secure::SecureVerifier::from_public_key(public_key)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// Verify a signature over a message.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.inner.verify(message, signature)
    }

    /// Verify a 128-byte receipt.
    fn verify_receipt(&self, data: &[u8]) -> bool {
        self.inner.verify_receipt(data)
    }

    /// The public key bytes.
    fn public_key<'p>(&self, py: Python<'p>) -> Bound<'p, PyBytes> {
        PyBytes::new(py, &self.inner.public_key())
    }

    fn __repr__(&self) -> String {
        "<SecureVerifier>".to_string()
    }
}

/// Constant-time byte equality.
///
/// `==` on Python bytes short-circuits, so the time it takes reveals how long a
/// shared prefix was. Use this when comparing a supplied digest or MAC against
/// the expected value.
#[pyfunction]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    core::secure::ct_eq(a, b)
}

/// Constant-time comparison of two strings, for hex digests and Merkle roots.
#[pyfunction]
fn ct_eq_str(a: &str, b: &str) -> bool {
    core::secure::ct_eq_str(a, b)
}

// ── Module ───────────────────────────────────────────────────────────────────

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add(
        "__doc__",
        "Native core for AetherProof. Optional; the pure-Python package works without it.",
    )?;
    m.add("RECEIPT_SIZE", core::RECEIPT_SIZE)?;
    m.add("SIGNED_PREFIX", core::SIGNED_PREFIX)?;
    m.add("LEAF_PREFIX", core::merkle::LEAF_PREFIX)?;
    m.add("NODE_PREFIX", core::merkle::NODE_PREFIX)?;

    m.add_function(wrap_pyfunction!(merkle_leaf, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_node, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_root, m)?)?;
    m.add_function(wrap_pyfunction!(inclusion_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_inclusion, m)?)?;

    m.add_function(wrap_pyfunction!(fnv1a, m)?)?;
    m.add_function(wrap_pyfunction!(generate_receipt, m)?)?;
    m.add_function(wrap_pyfunction!(verify_receipt, m)?)?;
    m.add_function(wrap_pyfunction!(receipt_size, m)?)?;

    m.add_function(wrap_pyfunction!(pq_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(pq_attach, m)?)?;
    m.add_function(wrap_pyfunction!(pq_verify, m)?)?;
    m.add_function(wrap_pyfunction!(pq_has_trailer, m)?)?;

    m.add_class::<PySecureSigner>()?;
    m.add_class::<PySecureVerifier>()?;
    m.add_function(wrap_pyfunction!(ct_eq, m)?)?;
    m.add_function(wrap_pyfunction!(ct_eq_str, m)?)?;
    Ok(())
}
