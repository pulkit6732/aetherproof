use aetherproof_core::pq::*;
use aetherproof_core::*;
use std::time::Instant;

fn main() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();
    let kp = PqKeypair::generate().expect("keygen");
    let core = to_bytes(&generate(1, b"model-bytes", 0, 1, &sk));
    let hybrid = attach(&core, &kp.private).expect("attach");

    println!("--- sizes ---");
    println!("core receipt (Ed25519 only) : {:6} bytes", core.len());
    println!("PQ trailer header           : {:6} bytes", PQ_HEADER_LEN);
    println!(
        "ML-DSA-65 signature         : {:6} bytes",
        trailer_sig(&hybrid).unwrap().len()
    );
    println!("hybrid receipt total        : {:6} bytes", hybrid.len());
    println!(
        "ML-DSA-65 public key        : {:6} bytes",
        kp.public_bytes().len()
    );

    let n = 500;
    let t = Instant::now();
    for _ in 0..n {
        let _ = attach(&core, &kp.private).unwrap();
    }
    let d = t.elapsed();
    println!("\n--- timings ({n} ops) ---");
    println!(
        "ML-DSA sign   : {:8.2} us/op  {:>8.0} ops/sec",
        d.as_secs_f64() * 1e6 / n as f64,
        n as f64 / d.as_secs_f64()
    );

    let t = Instant::now();
    for _ in 0..n {
        assert!(verify_pq(&hybrid, &kp.public));
    }
    let d = t.elapsed();
    println!(
        "ML-DSA verify : {:8.2} us/op  {:>8.0} ops/sec",
        d.as_secs_f64() * 1e6 / n as f64,
        n as f64 / d.as_secs_f64()
    );

    let t = Instant::now();
    for _ in 0..n {
        assert!(verify_hybrid(&hybrid, &vk, &kp.public));
    }
    let d = t.elapsed();
    println!(
        "hybrid verify : {:8.2} us/op  {:>8.0} ops/sec  (Ed25519 + ML-DSA)",
        d.as_secs_f64() * 1e6 / n as f64,
        n as f64 / d.as_secs_f64()
    );

    println!("\n--- backward compatibility ---");
    let old_view: &[u8; RECEIPT_SIZE] = hybrid[..RECEIPT_SIZE].try_into().unwrap();
    println!(
        "core bytes unchanged by attach : {}",
        hybrid[..RECEIPT_SIZE] == core[..]
    );
    println!("pre-PQ verifier accepts hybrid : {}", verify(old_view, &vk));
    println!(
        "hybrid verify without trailer  : {}",
        verify_hybrid(&core, &vk, &kp.public)
    );
}
