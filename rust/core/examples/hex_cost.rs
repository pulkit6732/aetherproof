use sha2::{Digest, Sha256};
use std::time::Instant;
const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_unsafe(d: &[u8]) -> String {
    let mut out = vec![0u8; d.len() * 2];
    for (i, b) in d.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    unsafe { String::from_utf8_unchecked(out) }
}
fn hex_safe(d: &[u8]) -> String {
    let mut out = vec![0u8; d.len() * 2];
    for (i, b) in d.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8(out).expect("HEX is ASCII by construction")
}
fn main() {
    let d = Sha256::digest(b"x");
    assert_eq!(hex_unsafe(&d), hex_safe(&d));
    const N: usize = 3_000_000;
    for _ in 0..200_000 {
        std::hint::black_box(hex_unsafe(&d));
    }
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(hex_unsafe(&d));
    }
    let u = t.elapsed().as_secs_f64() / N as f64 * 1e9;
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(hex_safe(&d));
    }
    let s = t.elapsed().as_secs_f64() / N as f64 * 1e9;
    println!("  unsafe from_utf8_unchecked : {u:6.2} ns/op");
    println!("  safe   from_utf8 + expect  : {s:6.2} ns/op");
    println!(
        "  cost of removing unsafe    : {:+.2} ns ({:+.1}%)",
        s - u,
        (s - u) / u * 100.0
    );
}
