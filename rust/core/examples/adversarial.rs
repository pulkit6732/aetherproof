//! Adversarial probe: hunt for panics, overflows, and fail-open paths.
use aetherproof_core::merkle::*;
use aetherproof_core::pq::*;
use aetherproof_core::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn probe(name: &str, f: impl FnOnce()) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => {
            println!("  ok    {name}");
            true
        }
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("?");
            println!("  PANIC {name}  <- {msg}");
            false
        }
    }
}

fn main() {
    let mut bad = 0;
    println!("=== PANIC PROBES: attacker-controlled input ===");

    // merkle
    if !probe("merkle_root([])", || {
        let _ = merkle_root(&[]);
    }) {
        bad += 1;
    }
    if !probe("build_levels([])", || {
        let _ = build_levels(&[]);
    }) {
        bad += 1;
    }
    if !probe("merkle_leaf(empty str)", || {
        let _ = merkle_leaf("");
    }) {
        bad += 1;
    }
    if !probe("merkle_leaf(1MB str)", || {
        let _ = merkle_leaf(&"a".repeat(1_000_000));
    }) {
        bad += 1;
    }
    if !probe("merkle_node(non-hex)", || {
        let _ = merkle_node("!!!", "\u{1F600}");
    }) {
        bad += 1;
    }
    if !probe("inclusion_proof([], 0)", || {
        let _ = inclusion_proof(&[], 0);
    }) {
        bad += 1;
    }
    if !probe("inclusion_proof(1, usize::MAX)", || {
        let _ = inclusion_proof(&["a".into()], usize::MAX);
    }) {
        bad += 1;
    }
    if !probe("verify_inclusion(empty proof)", || {
        let _ = verify_inclusion("x", &[], "y");
    }) {
        bad += 1;
    }
    if !probe("build_levels(1 leaf)", || {
        let _ = build_levels(&["a".into()]);
    }) {
        bad += 1;
    }

    // receipts
    if !probe("from_bytes(all zeros)", || {
        let _ = from_bytes(&[0u8; 128]);
    }) {
        bad += 1;
    }
    if !probe("from_bytes(all 0xFF)", || {
        let _ = from_bytes(&[0xFFu8; 128]);
    }) {
        bad += 1;
    }
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let vk = sk.verifying_key();
    if !probe("verify(all zeros)", || {
        let _ = verify(&[0u8; 128], &vk);
    }) {
        bad += 1;
    }
    if !probe("verify(all 0xFF)", || {
        let _ = verify(&[0xFFu8; 128], &vk);
    }) {
        bad += 1;
    }
    if !probe("generate(empty binary)", || {
        let _ = generate(0, b"", 0, 0, &sk);
    }) {
        bad += 1;
    }
    if !probe("generate(u32::MAX pid)", || {
        let _ = generate(u32::MAX, b"x", u64::MAX, u32::MAX, &sk);
    }) {
        bad += 1;
    }

    // PQ trailer - every field is attacker-controlled
    let core_r = to_bytes(&generate(1, b"m", 0, 1, &sk));
    if !probe("trailer_sig(core only)", || {
        let _ = trailer_sig(&core_r);
    }) {
        bad += 1;
    }
    if !probe("trailer_sig(empty)", || {
        let _ = trailer_sig(&[]);
    }) {
        bad += 1;
    }
    if !probe("trailer_sig(1 byte)", || {
        let _ = trailer_sig(&[0u8]);
    }) {
        bad += 1;
    }
    if !probe("has_trailer(empty)", || {
        let _ = has_trailer(&[]);
    }) {
        bad += 1;
    }
    if !probe("attach(wrong len)", || {
        let kp = PqKeypair::generate().unwrap();
        attach(&[0u8; 7], &kp.private).ok();
    }) {
        bad += 1;
    }

    // the dangerous one: attacker sets pq_sig_len to u32::MAX
    let mut evil = core_r.to_vec();
    evil.extend_from_slice(b"AETHPQ01");
    evil.push(1);
    evil.extend_from_slice(&[0u8; 3]);
    evil.extend_from_slice(&u32::MAX.to_le_bytes());
    if !probe("trailer_sig(sig_len=u32::MAX)", || {
        let _ = trailer_sig(&evil);
    }) {
        bad += 1;
    }
    let kp = PqKeypair::generate().unwrap();
    if !probe("verify_pq(sig_len=u32::MAX)", || {
        let _ = verify_pq(&evil, &kp.public);
    }) {
        bad += 1;
    }
    if !probe("verify_hybrid(sig_len=u32::MAX)", || {
        let _ = verify_hybrid(&evil, &vk, &kp.public);
    }) {
        bad += 1;
    }

    // header present but zero-length signature
    let mut zerolen = core_r.to_vec();
    zerolen.extend_from_slice(b"AETHPQ01");
    zerolen.push(1);
    zerolen.extend_from_slice(&[0u8; 3]);
    zerolen.extend_from_slice(&0u32.to_le_bytes());
    if !probe("verify_pq(sig_len=0)", || {
        let _ = verify_pq(&zerolen, &kp.public);
    }) {
        bad += 1;
    }
    if !probe("verify_hybrid(shorter than core)", || {
        let _ = verify_hybrid(&[0u8; 10], &vk, &kp.public);
    }) {
        bad += 1;
    }

    println!("\n=== FAIL-OPEN PROBES: must all be false ===");
    let mut open = 0;
    let mut chk = |name: &str, v: bool| {
        if v {
            println!("  FAIL-OPEN {name}");
            open += 1;
        } else {
            println!("  closed    {name}");
        }
    };
    chk("verify(zeros)", verify(&[0u8; 128], &vk));
    chk("verify_pq(no trailer)", verify_pq(&core_r, &kp.public));
    chk("verify_pq(sig_len=MAX)", verify_pq(&evil, &kp.public));
    chk("verify_pq(sig_len=0)", verify_pq(&zerolen, &kp.public));
    chk(
        "verify_hybrid(no trailer)",
        verify_hybrid(&core_r, &vk, &kp.public),
    );
    chk(
        "verify_hybrid(truncated)",
        verify_hybrid(&[0u8; 10], &vk, &kp.public),
    );
    chk(
        "verify_inclusion(empty proof, wrong root)",
        verify_inclusion("x", &[], "deadbeef"),
    );

    println!("\nPANICS: {bad}   FAIL-OPEN: {open}");
    if bad > 0 || open > 0 {
        std::process::exit(1);
    }
}
