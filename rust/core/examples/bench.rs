use aetherproof_core::*;
use std::time::Instant;

fn main() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();
    let n: u32 = 20_000;

    // sign
    let t = Instant::now();
    for i in 0..n {
        let _ = generate(i, b"model-bytes", 0, 1, &sk);
    }
    let d = t.elapsed();
    println!(
        "rust sign    : {:8.2} us/op   {:>9.0} ops/sec",
        d.as_secs_f64() * 1e6 / n as f64,
        n as f64 / d.as_secs_f64()
    );

    // verify
    let r = generate(1, b"model-bytes", 0, 1, &sk);
    let b = to_bytes(&r);
    let t = Instant::now();
    for _ in 0..n {
        let _ = verify(&b, &vk);
    }
    let d = t.elapsed();
    println!(
        "rust verify  : {:8.2} us/op   {:>9.0} ops/sec",
        d.as_secs_f64() * 1e6 / n as f64,
        n as f64 / d.as_secs_f64()
    );

    println!("receipt size : {:8} bytes", b.len());
}
