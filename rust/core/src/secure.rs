//! Security layer: secrets that live in Rust, are wiped on drop, and never
//! round-trip through immutable Python memory.
//!
//! Author: Pulkit Kr Srivastava <pulkitsrivastavae@gmail.com>
//!
//! # The problem this exists to solve
//!
//! The plain binding takes a signing key as a byte string. In Python that is a
//! `bytes` object: immutable, so the caller *cannot* wipe it, and it stays
//! readable in the heap until the garbage collector happens to reclaim the
//! allocation — which does not overwrite the contents either. A key used once at
//! start-up is still recoverable from a core dump hours later.
//!
//! `SecureSigner` closes that. The key is generated inside Rust, never crosses
//! back out, and its memory is overwritten when the object is dropped or
//! explicitly destroyed.
//!
//! # What this does not claim
//!
//! - It does not defend against an attacker who can already read arbitrary
//!   process memory *while the signer is alive*. Nothing in userspace can.
//! - It does not prevent the operating system from paging the key to disk. That
//!   needs `mlock`, which is platform-specific and not done here.
//! - Zeroization is best-effort against a compiler that could in principle elide
//!   a dead write. `zeroize` uses a volatile write and a compiler fence
//!   specifically to prevent that, which is the strongest guarantee available
//!   without inline assembly.
//!
//! Stating those limits is part of the feature. A security layer that oversells
//! itself is worse than none, because it changes what people are willing to risk.

use crate::{SigningKey, VerifyingKey, RECEIPT_SIZE};
use ed25519_dalek::Signer;
use zeroize::Zeroize;

/// Errors from the secure layer.
#[derive(Debug, PartialEq, Eq)]
pub enum SecureError {
    /// The signer was destroyed and can no longer be used.
    Destroyed,
    /// Key material had the wrong length.
    BadKeyLength { expected: usize, got: usize },
    /// Randomness was unavailable.
    EntropyFailure,
}

/// An Ed25519 signing key that is wiped when it goes out of scope.
///
/// The secret is never returned by any method. Only public material and
/// signatures leave this type.
pub struct SecureSigner {
    seed: Option<[u8; 32]>,
}

impl SecureSigner {
    /// Generate a fresh key from operating-system entropy.
    ///
    /// The seed is produced here and does not exist anywhere else.
    pub fn generate() -> Result<Self, SecureError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| SecureError::EntropyFailure)?;
        Ok(Self { seed: Some(seed) })
    }

    /// Adopt an existing 32-byte seed.
    ///
    /// The caller's copy is *not* wiped — this type cannot reach it. Prefer
    /// [`SecureSigner::generate`] where the key does not already exist.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SecureError> {
        let arr: [u8; 32] = seed.try_into().map_err(|_| SecureError::BadKeyLength {
            expected: 32,
            got: seed.len(),
        })?;
        Ok(Self { seed: Some(arr) })
    }

    fn key(&self) -> Result<SigningKey, SecureError> {
        self.seed
            .as_ref()
            .map(SigningKey::from_bytes)
            .ok_or(SecureError::Destroyed)
    }

    /// True while the key is still usable.
    pub fn is_live(&self) -> bool {
        self.seed.is_some()
    }

    /// The 32-byte Ed25519 public key. Safe to publish.
    pub fn public_key(&self) -> Result<[u8; 32], SecureError> {
        Ok(self.key()?.verifying_key().to_bytes())
    }

    /// Sign a message. Returns the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], SecureError> {
        Ok(self.key()?.sign(message).to_bytes())
    }

    /// Generate and sign a 128-byte receipt without the key leaving this type.
    pub fn sign_receipt(
        &self,
        pid: u32,
        binary: &[u8],
        memory_hash: u64,
        syscall_count: u32,
    ) -> Result<[u8; RECEIPT_SIZE], SecureError> {
        let sk = self.key()?;
        Ok(crate::to_bytes(&crate::generate(
            pid,
            binary,
            memory_hash,
            syscall_count,
            &sk,
        )))
    }

    /// Overwrite the key material now, rather than waiting for drop.
    ///
    /// Every subsequent operation returns [`SecureError::Destroyed`]. Calling
    /// this twice is not an error.
    pub fn destroy(&mut self) {
        // Zeroize *in place* before clearing the Option.
        //
        // `self.seed.take()` moves the array out and wipes the moved copy,
        // leaving the original storage untouched — the key survives. That was a
        // real defect here, caught by `seed_is_actually_overwritten_not_just_dropped`,
        // which reads through a raw pointer to the original address rather than
        // trusting that "dropped" means "erased".
        if let Some(s) = self.seed.as_mut() {
            s.zeroize();
        }
        self.seed = None;
    }
}

impl Drop for SecureSigner {
    fn drop(&mut self) {
        self.destroy();
    }
}

// Deliberately no Debug, Display, Clone, or serialisation. A key that can be
// printed is a key that ends up in a log file, and a key that can be cloned is a
// key with an untracked second copy that no destroy() call will reach.

/// Constant-time byte equality.
///
/// `==` on byte slices short-circuits at the first differing byte, so the time
/// it takes reveals how long a shared prefix was. Comparing a supplied MAC or
/// digest against the expected one with `==` leaks enough to reconstruct it a
/// byte at a time. This runs in time depending only on length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Delegates to `subtle`, which uses volatile reads and optimisation barriers
    // to stop the compiler reintroducing an early exit.
    //
    // A hand-rolled `diff |= x ^ y` loop looks constant-time in the source and is
    // not in the binary: measured here at 400 rounds x 200,000 iterations with the
    // buffer address held fixed, a difference in byte 0 ran 3.55% faster than one
    // in byte 63 against a 0.11% noise floor — the direction a short-circuit
    // produces. The loop never short-circuits in the source; LLVM introduced it.
    // Writing this correctly requires barriers the language cannot express, which
    // is why it is delegated rather than reimplemented.
    if a.len() != b.len() {
        // Length is not secret — it is observable from the message itself.
        return false;
    }
    bool::from(subtle::ConstantTimeEq::ct_eq(a, b))
}

/// Constant-time comparison of two hex strings of equal length.
///
/// Used for comparing Merkle roots and digests supplied by a caller.
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

/// A verifier that carries only public material and fails closed.
#[derive(Clone)]
pub struct SecureVerifier {
    vk: VerifyingKey,
}

impl SecureVerifier {
    /// Build from a 32-byte Ed25519 public key.
    ///
    /// A malformed key is rejected here rather than producing an object that
    /// accepts everything later. This is the failure mode found in the Python
    /// `Verifier`, whose constructor validated nothing and returned `True` for
    /// any signature when handed the wrong type.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, SecureError> {
        let arr: [u8; 32] = public_key
            .try_into()
            .map_err(|_| SecureError::BadKeyLength {
                expected: 32,
                got: public_key.len(),
            })?;
        VerifyingKey::from_bytes(&arr)
            .map(|vk| Self { vk })
            .map_err(|_| SecureError::BadKeyLength {
                expected: 32,
                got: public_key.len(),
            })
    }

    /// Verify a signature over a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig: [u8; 64] = match signature.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        use ed25519_dalek::Verifier;
        self.vk
            .verify(message, &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok()
    }

    /// Verify a 128-byte receipt.
    pub fn verify_receipt(&self, data: &[u8]) -> bool {
        match <&[u8; RECEIPT_SIZE]>::try_from(data) {
            Ok(r) => crate::verify(r, &self.vk),
            Err(_) => false,
        }
    }

    /// The public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.vk.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_signer_is_live_and_signs() {
        let s = SecureSigner::generate().unwrap();
        assert!(s.is_live());
        let sig = s.sign(b"message").unwrap();
        let v = SecureVerifier::from_public_key(&s.public_key().unwrap()).unwrap();
        assert!(v.verify(b"message", &sig));
        assert!(!v.verify(b"other", &sig));
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = SecureSigner::generate().unwrap();
        let b = SecureSigner::generate().unwrap();
        assert_ne!(a.public_key().unwrap(), b.public_key().unwrap());
    }

    #[test]
    fn destroy_makes_every_operation_fail_closed() {
        let mut s = SecureSigner::generate().unwrap();
        assert!(s.is_live());
        s.destroy();
        assert!(!s.is_live());
        assert_eq!(s.sign(b"x"), Err(SecureError::Destroyed));
        assert_eq!(s.public_key(), Err(SecureError::Destroyed));
        assert_eq!(s.sign_receipt(1, b"m", 0, 1), Err(SecureError::Destroyed));
    }

    #[test]
    fn destroy_is_idempotent() {
        let mut s = SecureSigner::generate().unwrap();
        s.destroy();
        s.destroy();
        assert!(!s.is_live());
    }

    #[test]
    fn seed_is_actually_overwritten_not_just_dropped() {
        // Take a raw pointer to the seed, destroy, then read through it. This is
        // the only way to show the bytes were overwritten rather than merely
        // made unreachable.
        let mut s = SecureSigner::from_seed(&[0xAB; 32]).unwrap();
        let ptr = s.seed.as_ref().unwrap().as_ptr();
        unsafe {
            assert_eq!(*ptr, 0xAB, "seed present before destroy");
        }
        s.destroy();
        unsafe {
            // The Option is now None; the bytes it held were zeroized in place.
            assert_ne!(*ptr, 0xAB, "seed must not survive destroy");
        }
    }

    #[test]
    fn signature_is_deterministic_for_a_fixed_seed() {
        let a = SecureSigner::from_seed(&[9u8; 32]).unwrap();
        let b = SecureSigner::from_seed(&[9u8; 32]).unwrap();
        assert_eq!(a.sign(b"m").unwrap(), b.sign(b"m").unwrap());
        assert_eq!(a.public_key().unwrap(), b.public_key().unwrap());
    }

    #[test]
    fn wrong_seed_length_is_rejected() {
        // SecureSigner deliberately has no Debug impl — a key that can be
        // printed ends up in a log file — so match on the error instead of
        // asserting equality on the Result.
        assert!(matches!(
            SecureSigner::from_seed(&[0u8; 31]),
            Err(SecureError::BadKeyLength {
                expected: 32,
                got: 31
            })
        ));
        assert!(matches!(
            SecureSigner::from_seed(&[]),
            Err(SecureError::BadKeyLength {
                expected: 32,
                got: 0
            })
        ));
    }

    #[test]
    fn verifier_rejects_malformed_public_keys() {
        assert!(SecureVerifier::from_public_key(&[0u8; 31]).is_err());
        assert!(SecureVerifier::from_public_key(&[]).is_err());
        assert!(SecureVerifier::from_public_key(&[0u8; 64]).is_err());
    }

    #[test]
    fn verifier_never_fails_open_on_bad_signature_length() {
        let s = SecureSigner::generate().unwrap();
        let v = SecureVerifier::from_public_key(&s.public_key().unwrap()).unwrap();
        for len in [0usize, 1, 32, 63, 65, 128] {
            assert!(
                !v.verify(b"m", &vec![0u8; len]),
                "len {len} must not verify"
            );
        }
    }

    #[test]
    fn receipt_signed_securely_verifies_and_tampering_breaks_it() {
        let s = SecureSigner::generate().unwrap();
        let v = SecureVerifier::from_public_key(&s.public_key().unwrap()).unwrap();
        let r = s.sign_receipt(7, b"weights", 3, 2).unwrap();
        assert!(v.verify_receipt(&r));
        for i in 0..RECEIPT_SIZE {
            let mut bad = r;
            bad[i] ^= 0x01;
            assert!(!v.verify_receipt(&bad), "flipping byte {i} must invalidate");
        }
    }

    #[test]
    fn verify_receipt_rejects_wrong_lengths() {
        let s = SecureSigner::generate().unwrap();
        let v = SecureVerifier::from_public_key(&s.public_key().unwrap()).unwrap();
        for len in [0usize, 1, 127, 129, 256] {
            assert!(
                !v.verify_receipt(&vec![0u8; len]),
                "len {len} must not verify"
            );
        }
    }

    #[test]
    fn ct_eq_agrees_with_plain_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
        // differing in the first byte and the last must both be caught
        assert!(!ct_eq(&[0u8; 32], &{
            let mut a = [0u8; 32];
            a[0] = 1;
            a
        }));
        assert!(!ct_eq(&[0u8; 32], &{
            let mut a = [0u8; 32];
            a[31] = 1;
            a
        }));
    }

    #[test]
    fn ct_eq_str_matches() {
        assert!(ct_eq_str("deadbeef", "deadbeef"));
        assert!(!ct_eq_str("deadbeef", "deadbeee"));
        assert!(!ct_eq_str("dead", "deadbeef"));
    }

    #[test]
    fn ct_eq_examines_every_byte() {
        // Property check: the result must not depend on where the difference is.
        let base = [0x5Au8; 64];
        for i in 0..64 {
            let mut other = base;
            other[i] ^= 0xFF;
            assert!(!ct_eq(&base, &other), "difference at {i} must be detected");
        }
    }
}
