//! Independent verification of the security layer's claims.
use aetherproof_core::secure::*;
use std::time::Instant;

fn main() {
    println!("=== 1. ZEROIZATION: scan the stack region for the key pattern ===");
    // A distinctive 32-byte pattern; search the surrounding stack after destroy.
    const MARK: u8 = 0xC7;
    let (before, after) = {
        let mut s = SecureSigner::from_seed(&[MARK; 32]).unwrap();
        let probe = |addr: *const u8, n: usize| -> usize {
            let mut runs = 0;
            unsafe {
                let sl = std::slice::from_raw_parts(addr, n);
                for w in sl.windows(32) { if w.iter().all(|&b| b == MARK) { runs += 1; } }
            }
            runs
        };
        let base = &s as *const _ as *const u8;
        let b = probe(base, 256);
        s.destroy();
        let a = probe(base, 256);
        (b, a)
    };
    println!("   32-byte runs of 0x{MARK:02X} near the signer, before destroy : {before}");
    println!("   32-byte runs of 0x{MARK:02X} near the signer, after  destroy : {after}");
    let zero_ok = before > 0 && after == 0;
    println!("   {}", if zero_ok { "PASS  key overwritten in place" } else { "FAIL  key survived" });

    println!("\n=== 2. DROP also wipes (no explicit destroy) ===");
    let addr = {
        let s = SecureSigner::from_seed(&[0xD3; 32]).unwrap();
        &s as *const _ as usize
    }; // dropped here
    let survived = unsafe {
        std::slice::from_raw_parts(addr as *const u8, 64)
            .windows(32).any(|w| w.iter().all(|&b| b == 0xD3))
    };
    println!("   key pattern present after drop : {survived}");
    println!("   {}", if !survived { "PASS  Drop wipes" } else { "FAIL  Drop leaked" });

    println!("\n=== 3. CONSTANT-TIME comparison: does timing leak the prefix? ===");
    let base = [0x5Au8; 64];
    let mut early = base; early[0] ^= 0xFF;   // differs at byte 0
    let mut late  = base; late[63] ^= 0xFF;   // differs at byte 63
    const R: usize = 3_000_000;

    // warm up
    for _ in 0..100_000 { std::hint::black_box(ct_eq(&base, &early)); }

    let t = Instant::now();
    for _ in 0..R { std::hint::black_box(ct_eq(&base, &early)); }
    let d_early = t.elapsed().as_secs_f64() / R as f64 * 1e9;

    let t = Instant::now();
    for _ in 0..R { std::hint::black_box(ct_eq(&base, &late)); }
    let d_late = t.elapsed().as_secs_f64() / R as f64 * 1e9;

    // naive == for contrast
    let t = Instant::now();
    for _ in 0..R { std::hint::black_box(base[..] == early[..]); }
    let n_early = t.elapsed().as_secs_f64() / R as f64 * 1e9;
    let t = Instant::now();
    for _ in 0..R { std::hint::black_box(base[..] == late[..]); }
    let n_late = t.elapsed().as_secs_f64() / R as f64 * 1e9;

    let ct_skew = (d_early - d_late).abs() / d_early.max(d_late) * 100.0;
    println!("   ct_eq   differ@0 {d_early:6.2} ns   differ@63 {d_late:6.2} ns   skew {ct_skew:5.2}%");
    println!("   ==      differ@0 {n_early:6.2} ns   differ@63 {n_late:6.2} ns");
    let ct_ok = ct_skew < 10.0;
    println!("   {}", if ct_ok { "PASS  no position-dependent timing above noise" } else { "REVIEW skew above threshold" });

    println!("\n=== 4. FAIL-CLOSED after destroy ===");
    let mut s = SecureSigner::generate().unwrap();
    s.destroy();
    let closed = s.sign(b"x").is_err() && s.public_key().is_err() && s.sign_receipt(1,b"m",0,1).is_err();
    println!("   every operation errors : {closed}");
    println!("   {}", if closed { "PASS" } else { "FAIL" });

    println!("\n=== 5. VERIFIER cannot be built from bad key material ===");
    let rejected = [0usize,1,16,31,33,64].iter()
        .all(|&n| SecureVerifier::from_public_key(&vec![0u8; n]).is_err());
    println!("   malformed public keys rejected at construction : {rejected}");
    println!("   {}", if rejected { "PASS  fails closed at build time, not verify time" } else { "FAIL" });

    let all = zero_ok && !survived && ct_ok && closed && rejected;
    println!("\nOVERALL: {}", if all { "PASS" } else { "FAIL" });
    if !all { std::process::exit(1); }
}
