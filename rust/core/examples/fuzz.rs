//! Randomised fuzz campaign over every attacker-reachable parser.
use aetherproof_core::merkle::*;
use aetherproof_core::pq::*;
use aetherproof_core::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

// xorshift64* — deterministic, seeded, no external dep
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn byte(&mut self) -> u8 { (self.next() & 0xff) as u8 }
    fn upto(&mut self, n: usize) -> usize { if n == 0 { 0 } else { (self.next() as usize) % n } }
    fn bytes(&mut self, n: usize) -> Vec<u8> { (0..n).map(|_| self.byte()).collect() }
}

fn main() {
    let _seed = Rng(0x9E3779B97F4A7C15);
    let sk = SigningKey::from_bytes(&[5u8; 32]);
    let vk = sk.verifying_key();
    let kp = PqKeypair::generate().unwrap();
    let good_core = to_bytes(&generate(1, b"m", 0, 1, &sk));
    let good_hybrid = attach(&good_core, &kp.private).unwrap();

    let mut panics = 0usize;
    let mut accepted_garbage = 0usize;
    const N: usize = 200_000;

    for i in 0..N {
        let r = catch_unwind(AssertUnwindSafe(|| {
            let mut rng = Rng(0x9E3779B97F4A7C15 ^ (i as u64).wrapping_mul(0x100000001B3));
            match rng.upto(8) {
                // wholly random buffers of random length
                0 => { let n = rng.upto(600); let b = rng.bytes(n);
                       let _ = has_trailer(&b); let _ = trailer_sig(&b);
                       let _ = verify_pq(&b, &kp.public); let _ = verify_hybrid(&b, &vk, &kp.public); }
                // valid core, corrupted trailer header
                1 => { let mut b = good_hybrid.clone();
                       for _ in 0..rng.upto(8) { let p = 128 + rng.upto(16); b[p] = rng.byte(); }
                       let _ = trailer_sig(&b); let _ = verify_pq(&b, &kp.public); }
                // valid trailer, random declared length
                2 => { let mut b = good_hybrid.clone();
                       let l = (rng.next() as u32).to_le_bytes();
                       b[140..144].copy_from_slice(&l);
                       let _ = trailer_sig(&b); let _ = verify_pq(&b, &kp.public); }
                // truncation at every possible offset
                3 => { let n = rng.upto(good_hybrid.len() + 1);
                       let b = &good_hybrid[..n];
                       let _ = trailer_sig(b); let _ = verify_pq(b, &kp.public);
                       let _ = verify_hybrid(b, &vk, &kp.public); }
                // random 128-byte receipts
                4 => { let mut b = [0u8; 128]; for x in b.iter_mut() { *x = rng.byte(); }
                       let _ = from_bytes(&b); let _ = verify(&b, &vk); }
                // random hex-ish merkle input
                5 => { let n = rng.upto(40);
                       let l: Vec<String> = (0..n).map(|_| {
                           let len = rng.upto(80);
                           rng.bytes(len).iter().map(|b| format!("{b:02x}")).collect()
                       }).collect();
                       let root = merkle_root(&l);
                       if !l.is_empty() { let i = rng.upto(l.len());
                           if let Some(p) = inclusion_proof(&l, i) { let _ = verify_inclusion(&l[i], &p, &root); } } }
                // arbitrary unicode into the hashers
                6 => { let k = rng.upto(200); let s = String::from_utf8_lossy(&rng.bytes(k)).to_string();
                       let _ = merkle_leaf(&s); let _ = merkle_node(&s, &s); }
                // oversized declared length with real bytes after
                _ => { let mut b = good_core.to_vec();
                       b.extend_from_slice(b"AETHPQ01"); b.push(rng.byte());
                       b.extend_from_slice(&[0u8; 3]);
                       b.extend_from_slice(&(rng.next() as u32).to_le_bytes());
                       let k = rng.upto(4000); b.extend(rng.bytes(k));
                       let _ = trailer_sig(&b); let _ = verify_pq(&b, &kp.public);
                       let _ = verify_hybrid(&b, &vk, &kp.public); }
            }
        }));
        if r.is_err() { panics += 1; if panics <= 3 { println!("  PANIC at iteration {i}"); } }
    }

    // Separately: no random buffer may ever verify.
    for i in 0..50_000usize {
        let mut rng = Rng(0xDEADBEEF ^ i as u64);
        let mut b = [0u8; 128]; for x in b.iter_mut() { *x = rng.byte(); }
        if verify(&b, &vk) { accepted_garbage += 1; }
        let n = rng.upto(4000); let g = rng.bytes(n);
        if verify_pq(&g, &kp.public) { accepted_garbage += 1; }
        if verify_hybrid(&g, &vk, &kp.public) { accepted_garbage += 1; }
    }

    println!("\niterations      : {N} parser + 150,000 verifier");
    println!("panics          : {panics}");
    println!("garbage accepted: {accepted_garbage}");
    if panics > 0 || accepted_garbage > 0 { std::process::exit(1); }
    println!("\nRESULT: no panic, no forgery, across 350,000 adversarial inputs");
}
