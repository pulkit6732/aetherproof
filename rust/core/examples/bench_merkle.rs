use aetherproof_core::merkle::*;
use sha2::{Digest, Sha256};
use std::time::Instant;

fn leaves(n: usize) -> Vec<String> {
    (0..n).map(|i| Sha256::digest(format!("turn-{i}")).iter().map(|b| format!("{b:02x}")).collect()).collect()
}

fn main() {
    for n in [1_000usize, 10_000, 50_000] {
        let l = leaves(n);
        let t = Instant::now(); let root = merkle_root(&l); let build = t.elapsed();
        let t = Instant::now();
        for i in (0..n).step_by(n / 100) { let _ = inclusion_proof(&l, i).unwrap(); }
        let proofs = t.elapsed();
        let p = inclusion_proof(&l, n / 2).unwrap();
        let t = Instant::now();
        for _ in 0..1000 { assert!(verify_inclusion(&l[n / 2], &p, &root)); }
        let ver = t.elapsed();
        println!("n={n:<6}  build {:7.2} ms   proof {:6.2} us/ea   verify {:6.2} us   siblings {:2}",
            build.as_secs_f64()*1e3, proofs.as_secs_f64()*1e6/100.0,
            ver.as_secs_f64()*1e6/1000.0, p.len());
    }
}
