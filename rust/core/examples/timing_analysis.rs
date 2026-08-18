//! Interleaved timing analysis with address and alignment controlled.
//!
//! The previous version compared two *different* stack buffers, so cache-line
//! alignment differed between the arms and showed up as a 6% skew in the wrong
//! direction (differing at byte 0 appeared slower, the opposite of a
//! short-circuit leak). Here a single buffer is mutated in place between
//! measurements, so both arms use the identical address and alignment and the
//! only variable is where the differing byte sits.
use aetherproof_core::secure::ct_eq;
use std::time::Instant;

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n.is_multiple_of(2) {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

fn main() {
    let base = [0x5Au8; 64];
    let mut probe = base; // one buffer, one address
    const ROUNDS: usize = 400;
    const INNER: usize = 200_000;

    let mut t0 = Vec::with_capacity(ROUNDS); // differs at byte 0
    let mut t63 = Vec::with_capacity(ROUNDS); // differs at byte 63
    let mut teq = Vec::with_capacity(ROUNDS); // fully equal

    for _ in 0..50_000 {
        std::hint::black_box(ct_eq(&base, &probe));
    }

    let time_it = |probe: &[u8; 64]| {
        let t = Instant::now();
        for _ in 0..INNER {
            std::hint::black_box(ct_eq(&base, probe));
        }
        t.elapsed().as_secs_f64() / INNER as f64 * 1e9
    };

    for r in 0..ROUNDS {
        // rotate which arm is measured first so ordering bias cancels
        let order = r % 3;
        let mut sample = |which: usize| -> f64 {
            probe = base;
            match which {
                0 => probe[0] ^= 0xFF,
                1 => probe[63] ^= 0xFF,
                _ => {}
            }
            time_it(&probe)
        };
        let (a, b, c) = (order, (order + 1) % 3, (order + 2) % 3);
        let va = sample(a);
        let vb = sample(b);
        let vc = sample(c);
        for (which, v) in [(a, va), (b, vb), (c, vc)] {
            match which {
                0 => t0.push(v),
                1 => t63.push(v),
                _ => teq.push(v),
            }
        }
    }

    let m0 = median(&mut t0);
    let m63 = median(&mut t63);
    let meq = median(&mut teq);
    let skew = (m0 - m63).abs() / m0.max(m63) * 100.0;

    let mut spread: Vec<f64> = t0.windows(2).map(|w| (w[0] - w[1]).abs()).collect();
    let noise = median(&mut spread) / m0 * 100.0;

    println!("single buffer, identical address; {ROUNDS} rounds x {INNER} inner, medians\n");
    println!("  differ at byte 0    : {m0:6.3} ns");
    println!("  differ at byte 63   : {m63:6.3} ns");
    println!("  fully equal         : {meq:6.3} ns");
    println!("\n  position skew (byte0 vs byte63) : {skew:5.2}%");
    println!("  within-arm noise floor          : {noise:5.2}%");
    println!(
        "\n  {}",
        if skew <= noise.max(2.0) {
            "PASS  no position-dependent timing above the measurement noise floor"
        } else {
            "INVESTIGATE  skew exceeds noise"
        }
    );
    println!("\n  Note: a short-circuit leak makes an early difference FASTER.");
    println!(
        "  Here byte0 vs byte63 is {}.",
        if m0 < m63 * 0.98 {
            "faster - consistent with a leak"
        } else if m0 > m63 * 1.02 {
            "slower - inconsistent with a leak"
        } else {
            "indistinguishable"
        }
    );
}
