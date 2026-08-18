//! Post-quantum signature slot — ML-DSA-65 (FIPS 204).
//!
//! Author: Pulkit Kr Srivastava <pulkitsrivastavae@gmail.com>
//!
//! # Why a second slot rather than a replacement
//!
//! Ed25519 is not broken today. ML-DSA is standardised but young. Signing under
//! both means a receipt survives either one failing: a break in Ed25519 leaves the
//! ML-DSA signature intact, and a flaw found in ML-DSA leaves Ed25519 intact.
//!
//! # Wire layout
//!
//! The 128-byte core receipt is unchanged. A hybrid receipt appends a trailer:
//!
//! ```text
//! [0..128]     core receipt          128-byte Ed25519-signed record (unchanged)
//! [128..136]   pq_magic              "AETHPQ01"
//! [136]        pq_alg                1 = ML-DSA-65
//! [137..140]   _pad                  [0; 3]
//! [140..144]   pq_sig_len            u32 little-endian
//! [144..]      pq_sig                ML-DSA-65 signature over core[0..64]
//! ```
//!
//! Both signatures cover the **same** preimage — bytes `[0..64]` of the core
//! receipt. There is one signed message, not two, so the signatures cannot
//! disagree about what was signed.
//!
//! A verifier that does not know about the trailer reads the first 128 bytes and
//! verifies Ed25519 exactly as before. Old receipts stay valid; new receipts stay
//! readable by old verifiers.

use crate::{RECEIPT_SIZE, SIGNED_PREFIX};

/// Re-exported so binding crates use exactly this version of the FIPS 204
/// implementation rather than resolving their own.
pub use fips204;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as PqSigner, Verifier as PqVerifier};

/// Magic marking the start of a post-quantum trailer.
pub const PQ_MAGIC: [u8; 8] = *b"AETHPQ01";

/// Algorithm identifier for ML-DSA-65 (FIPS 204).
pub const PQ_ALG_ML_DSA_65: u8 = 1;

/// Byte offset of the trailer header within a hybrid receipt.
pub const PQ_HEADER_OFF: usize = RECEIPT_SIZE;

/// Length of the trailer header preceding the signature bytes.
pub const PQ_HEADER_LEN: usize = 16;

/// Errors from post-quantum signing or verification.
#[derive(Debug, PartialEq, Eq)]
pub enum PqError {
    /// Buffer is shorter than a core receipt plus a trailer header.
    TooShort,
    /// Trailer magic did not match [`PQ_MAGIC`].
    BadMagic,
    /// Algorithm byte is not a value this build understands.
    UnknownAlg(u8),
    /// Declared signature length does not match the bytes present.
    LengthMismatch,
    /// Key material could not be decoded.
    BadKey,
    /// The signing operation failed.
    SignFailed,
}

/// An ML-DSA-65 keypair.
pub struct PqKeypair {
    pub public: ml_dsa_65::PublicKey,
    pub private: ml_dsa_65::PrivateKey,
}

impl PqKeypair {
    /// Generate a fresh ML-DSA-65 keypair.
    pub fn generate() -> Result<Self, PqError> {
        let (public, private) = ml_dsa_65::try_keygen().map_err(|_| PqError::BadKey)?;
        Ok(Self { public, private })
    }

    /// Serialise the public key.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.clone().into_bytes().to_vec()
    }
}

/// Sign the core receipt's signed prefix with ML-DSA-65 and return a hybrid receipt.
///
/// `core` must be exactly [`RECEIPT_SIZE`] bytes. The returned buffer is the core
/// receipt followed by the post-quantum trailer.
pub fn attach(core: &[u8], sk: &ml_dsa_65::PrivateKey) -> Result<Vec<u8>, PqError> {
    if core.len() != RECEIPT_SIZE {
        return Err(PqError::TooShort);
    }
    let sig = sk
        .try_sign(&core[..SIGNED_PREFIX], &[])
        .map_err(|_| PqError::SignFailed)?;

    let mut out = Vec::with_capacity(RECEIPT_SIZE + PQ_HEADER_LEN + sig.len());
    out.extend_from_slice(core);
    out.extend_from_slice(&PQ_MAGIC);
    out.push(PQ_ALG_ML_DSA_65);
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    out.extend_from_slice(&sig);
    Ok(out)
}

/// True if `data` carries a well-formed post-quantum trailer.
pub fn has_trailer(data: &[u8]) -> bool {
    data.len() >= RECEIPT_SIZE + PQ_HEADER_LEN && data[PQ_HEADER_OFF..PQ_HEADER_OFF + 8] == PQ_MAGIC
}

/// Extract the post-quantum signature bytes from a hybrid receipt.
pub fn trailer_sig(data: &[u8]) -> Result<&[u8], PqError> {
    if data.len() < RECEIPT_SIZE + PQ_HEADER_LEN {
        return Err(PqError::TooShort);
    }
    if data[PQ_HEADER_OFF..PQ_HEADER_OFF + 8] != PQ_MAGIC {
        return Err(PqError::BadMagic);
    }
    let alg = data[PQ_HEADER_OFF + 8];
    if alg != PQ_ALG_ML_DSA_65 {
        return Err(PqError::UnknownAlg(alg));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&data[PQ_HEADER_OFF + 12..PQ_HEADER_OFF + 16]);
    let sig_len = u32::from_le_bytes(len_bytes) as usize;

    let start = RECEIPT_SIZE + PQ_HEADER_LEN;
    if data.len() != start + sig_len {
        return Err(PqError::LengthMismatch);
    }
    Ok(&data[start..])
}

/// Verify only the post-quantum signature over the core receipt's signed prefix.
///
/// This does **not** check the Ed25519 signature. Use [`verify_hybrid`] to require
/// both.
pub fn verify_pq(data: &[u8], pk: &ml_dsa_65::PublicKey) -> bool {
    let sig = match trailer_sig(data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    pk.verify(&data[..SIGNED_PREFIX], &sig_arr, &[])
}

/// Verify a hybrid receipt: **both** the Ed25519 signature and the ML-DSA signature
/// must be valid over the same signed prefix.
///
/// Returns `false` if either signature fails, or if no trailer is present — a
/// caller asking for hybrid verification is asking for both, so a missing
/// post-quantum signature is a failure, not a pass.
pub fn verify_hybrid(
    data: &[u8],
    ed_vk: &crate::VerifyingKey,
    pq_pk: &ml_dsa_65::PublicKey,
) -> bool {
    if data.len() < RECEIPT_SIZE {
        return false;
    }
    let core: &[u8; RECEIPT_SIZE] = match data[..RECEIPT_SIZE].try_into() {
        Ok(c) => c,
        Err(_) => return false,
    };
    crate::verify(core, ed_vk) && verify_pq(data, pq_pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate, to_bytes, SigningKey};

    fn core_receipt() -> (Vec<u8>, crate::VerifyingKey) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let r = generate(42, b"model-bytes", 7, 3, &sk);
        (to_bytes(&r).to_vec(), vk)
    }

    #[test]
    fn core_receipt_is_unchanged_by_attaching() {
        let (core, _) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let hybrid = attach(&core, &kp.private).unwrap();
        assert_eq!(
            &hybrid[..RECEIPT_SIZE],
            &core[..],
            "attaching a PQ trailer must not alter the 128-byte core"
        );
    }

    #[test]
    fn old_verifier_still_accepts_hybrid_core() {
        let (core, vk) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let hybrid = attach(&core, &kp.private).unwrap();
        assert!(
            crate::verify(hybrid[..RECEIPT_SIZE].try_into().unwrap(), &vk),
            "a verifier that knows nothing about the trailer must still verify"
        );
    }

    #[test]
    fn hybrid_verifies_under_both_algorithms() {
        let (core, vk) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let hybrid = attach(&core, &kp.private).unwrap();
        assert!(
            verify_pq(&hybrid, &kp.public),
            "ML-DSA signature must verify"
        );
        assert!(
            verify_hybrid(&hybrid, &vk, &kp.public),
            "hybrid verification must accept a correctly signed receipt"
        );
    }

    #[test]
    fn hybrid_rejects_wrong_pq_key() {
        let (core, vk) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let other = PqKeypair::generate().unwrap();
        let hybrid = attach(&core, &kp.private).unwrap();
        assert!(!verify_pq(&hybrid, &other.public));
        assert!(!verify_hybrid(&hybrid, &vk, &other.public));
    }

    #[test]
    fn hybrid_fails_closed_without_trailer() {
        let (core, vk) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        assert!(
            !verify_hybrid(&core, &vk, &kp.public),
            "hybrid verification must fail when the PQ signature is absent"
        );
    }

    #[test]
    fn tampering_the_core_breaks_both_signatures() {
        let (core, vk) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let mut hybrid = attach(&core, &kp.private).unwrap();
        hybrid[16] ^= 0xFF; // flip a byte inside the signed prefix
        assert!(!crate::verify(
            hybrid[..RECEIPT_SIZE].try_into().unwrap(),
            &vk
        ));
        assert!(!verify_pq(&hybrid, &kp.public));
        assert!(!verify_hybrid(&hybrid, &vk, &kp.public));
    }

    #[test]
    fn flipping_any_pq_signature_byte_invalidates() {
        let (core, _) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let hybrid = attach(&core, &kp.private).unwrap();
        let start = RECEIPT_SIZE + PQ_HEADER_LEN;
        // Sample across the signature rather than all ~3.3k bytes, to keep the
        // suite fast while still covering the whole range.
        for i in (start..hybrid.len()).step_by(97) {
            let mut bad = hybrid.clone();
            bad[i] ^= 0x01;
            assert!(
                !verify_pq(&bad, &kp.public),
                "flipping PQ signature byte {i} must invalidate"
            );
        }
    }

    #[test]
    fn bad_magic_is_rejected() {
        let (core, _) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let mut hybrid = attach(&core, &kp.private).unwrap();
        hybrid[PQ_HEADER_OFF] = b'X';
        assert_eq!(trailer_sig(&hybrid), Err(PqError::BadMagic));
        assert!(!has_trailer(&hybrid));
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let (core, _) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let mut hybrid = attach(&core, &kp.private).unwrap();
        hybrid[PQ_HEADER_OFF + 8] = 0xEE;
        assert_eq!(trailer_sig(&hybrid), Err(PqError::UnknownAlg(0xEE)));
    }

    #[test]
    fn declared_length_must_match_bytes_present() {
        let (core, _) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let mut hybrid = attach(&core, &kp.private).unwrap();
        hybrid.pop(); // one byte short of the declared length
        assert_eq!(trailer_sig(&hybrid), Err(PqError::LengthMismatch));
        assert!(!verify_pq(&hybrid, &kp.public));
    }

    #[test]
    fn truncated_trailer_is_rejected() {
        let (core, _) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let hybrid = attach(&core, &kp.private).unwrap();
        let truncated = &hybrid[..RECEIPT_SIZE + 4];
        assert_eq!(trailer_sig(truncated), Err(PqError::TooShort));
        assert!(!verify_pq(truncated, &kp.public));
    }

    #[test]
    fn both_algorithms_sign_the_same_preimage() {
        // The security argument depends on there being exactly one signed message.
        let (core, _) = core_receipt();
        let kp = PqKeypair::generate().unwrap();
        let hybrid = attach(&core, &kp.private).unwrap();
        let sig = trailer_sig(&hybrid).unwrap();
        let sig_arr: [u8; ml_dsa_65::SIG_LEN] = sig.try_into().unwrap();
        // Verifies over the signed prefix, and not over the whole core.
        assert!(kp.public.verify(&core[..SIGNED_PREFIX], &sig_arr, &[]));
        assert!(!kp.public.verify(&core[..], &sig_arr, &[]));
    }
}
