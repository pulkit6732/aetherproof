use aetherproof_core::merkle::*;
use sha2::{Digest, Sha256};
use std::time::Instant;
fn main() {
    let l: Vec<String> = (0..50000)
        .map(|i| {
            Sha256::digest(format!("turn-{i}"))
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
        .collect();
    let _ = merkle_root(&l); // warm
    let mut runs: Vec<f64> = (0..7)
        .map(|_| {
            let t = Instant::now();
            let _ = merkle_root(&l);
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    let raw = runs.clone();
    runs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "rust build   : median {:7.2} ms   min {:7.2}  max {:7.2}",
        runs[3], runs[0], runs[6]
    );
    println!(
        "               runs: {:?}",
        raw.iter()
            .map(|x| (x * 10.0).round() / 10.0)
            .collect::<Vec<_>>()
    );

    let root = merkle_root(&l);
    let pr = inclusion_proof(&l, 25000).unwrap();
    for _ in 0..2000 {
        std::hint::black_box(verify_inclusion(&l[25000], &pr, &root));
    }
    let mut v: Vec<f64> = (0..7)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..5000 {
                std::hint::black_box(verify_inclusion(&l[25000], &pr, &root));
            }
            t.elapsed().as_secs_f64() / 5000.0 * 1e6
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "rust verify  : median {:6.2} us   siblings {}",
        v[3],
        pr.len()
    );
}
