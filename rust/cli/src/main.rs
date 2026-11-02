// AetherProof CLI
// Author: Pulkit Kr Srivastava <pulkitsrivastavae@gmail.com>

//! aetherproof CLI - generate, verify, benchmark, and self-test AetherProof receipts.
//!
//! Commands
//!   verify   <receipt.bin> (--pubkey <file> | --demo)       verify a 128-byte receipt
//!   generate --binary <file> (--key <file> | --demo) [--pid N]
//!            [--memory-hash H] [--syscall-count N]          generate + sign a receipt
//!            [--out receipt.bin]
//!   self-test                                     run all internal correctness checks
//!   bench    [--count N]                          measure receipts/second (default 50000)
//!
//! Keys: `--key` is a file holding a 32-byte Ed25519 seed (e.g. `openssl rand 32 > key`);
//! `--pubkey` is the 32-byte public key that `generate` writes next to the receipt
//! as `<out>.pub`. The built-in demo key is public, so it is refused unless `--demo`
//! is passed, and everything it signs is labelled as proving nothing.

use aetherproof_core::{
    dev_signing_key, dev_verifying_key, fnv1a, from_bytes, generate, tamper_probe, to_bytes,
    verify, SigningKey, VerifyingKey, RECEIPT_SIZE,
};
use std::{env, fs, process, time::Instant};

const DEMO_WARNING: &str =
    "WARNING: using the PUBLIC demo key. Anyone can forge receipts for it; this proves nothing.";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_help();
        process::exit(0);
    }

    match args[0].as_str() {
        "verify" => cmd_verify(&args[1..]),
        "generate" => cmd_generate(&args[1..]),
        "self-test" => cmd_self_test(),
        "bench" => cmd_bench(&args[1..]),
        other => {
            eprintln!("error: unknown command '{other}'. Try 'aetherproof --help'");
            process::exit(1);
        }
    }
}

// ── verify ─────────────────────────────────────────────────────────────────────

fn cmd_verify(args: &[String]) {
    let mut path: Option<String> = None;
    let mut pubkey: Option<String> = None;
    let mut demo = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pubkey" => {
                pubkey = Some(flag_value(args, i, "--pubkey"));
                i += 1;
            }
            "--demo" => demo = true,
            other if other.starts_with("--") => {
                eprintln!("error: unknown flag '{other}'");
                process::exit(1);
            }
            other => path = Some(other.to_string()),
        }
        i += 1;
    }
    let path = path.unwrap_or_else(|| {
        eprintln!("usage: aetherproof verify <receipt.bin> (--pubkey <file> | --demo)");
        process::exit(1);
    });
    let vk = verifying_key(pubkey.as_deref(), demo);

    let raw = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{path}': {e}");
        process::exit(2);
    });

    if raw.len() != RECEIPT_SIZE {
        eprintln!("error: expected {RECEIPT_SIZE} bytes, got {}", raw.len());
        process::exit(2);
    }

    let data: &[u8; RECEIPT_SIZE] = raw[..RECEIPT_SIZE].try_into().unwrap();

    let receipt = match from_bytes(data) {
        Some(r) => r,
        None => {
            eprintln!("error: invalid receipt magic or version");
            process::exit(2);
        }
    };

    let valid = verify(data, &vk);
    print_receipt_table(&receipt, valid, demo);
    process::exit(if valid { 0 } else { 1 });
}

// ── keys ───────────────────────────────────────────────────────────────────────

fn flag_value(args: &[String], i: usize, flag: &str) -> String {
    args.get(i + 1).cloned().unwrap_or_else(|| {
        eprintln!("error: {flag} needs a value");
        process::exit(1);
    })
}

fn read_32(path: &str, what: &str) -> [u8; 32] {
    let raw = fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {what} '{path}': {e}");
        process::exit(2);
    });
    raw.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!(
            "error: {what} '{path}' must be exactly 32 bytes, got {}",
            raw.len()
        );
        process::exit(2);
    })
}

fn key_choice_or_exit(file: Option<&str>, demo: bool, flag: &str) {
    match (file, demo) {
        (Some(_), true) => {
            eprintln!("error: pass either {flag} or --demo, not both");
            process::exit(1);
        }
        (None, false) => {
            eprintln!(
                "error: {flag} <file> is required. The built-in demo key is public and proves nothing; \
                 pass --demo only for testing."
            );
            process::exit(1);
        }
        _ => {}
    }
}

fn signing_key(file: Option<&str>, demo: bool) -> SigningKey {
    key_choice_or_exit(file, demo, "--key");
    match file {
        Some(f) => SigningKey::from_bytes(&read_32(f, "signing key")),
        None => {
            eprintln!("{DEMO_WARNING}");
            dev_signing_key()
        }
    }
}

fn verifying_key(file: Option<&str>, demo: bool) -> VerifyingKey {
    key_choice_or_exit(file, demo, "--pubkey");
    match file {
        Some(f) => VerifyingKey::from_bytes(&read_32(f, "public key")).unwrap_or_else(|_| {
            eprintln!("error: '{f}' is not a valid Ed25519 public key");
            process::exit(2);
        }),
        None => {
            eprintln!("{DEMO_WARNING}");
            dev_verifying_key()
        }
    }
}

// ── generate ───────────────────────────────────────────────────────────────────

fn cmd_generate(args: &[String]) {
    let mut binary_path: Option<String> = None;
    let mut pid: u32 = 1;
    let mut memory_hash: u64 = 0;
    let mut syscall_count: u32 = 0;
    let mut out_path: String = "receipt.bin".to_string();
    let mut key_path: Option<String> = None;
    let mut demo = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                key_path = Some(flag_value(args, i, "--key"));
                i += 1;
            }
            "--demo" => demo = true,
            "--binary" => {
                i += 1;
                binary_path = Some(args[i].clone());
            }
            "--pid" => {
                i += 1;
                pid = args[i].parse().unwrap_or(1);
            }
            "--memory-hash" => {
                i += 1;
                memory_hash = parse_u64_hex_or_dec(&args[i]);
            }
            "--syscall-count" => {
                i += 1;
                syscall_count = args[i].parse().unwrap_or(0);
            }
            "--out" => {
                i += 1;
                out_path = args[i].clone();
            }
            other => {
                eprintln!("error: unknown flag '{other}'");
                process::exit(1);
            }
        }
        i += 1;
    }

    let path = binary_path.unwrap_or_else(|| {
        eprintln!("error: --binary <file> is required");
        process::exit(1);
    });
    let sk = signing_key(key_path.as_deref(), demo);

    let binary = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{path}': {e}");
        process::exit(2);
    });

    let receipt = generate(pid, &binary, memory_hash, syscall_count, &sk);
    let bytes = to_bytes(&receipt);

    // Verify immediately to catch signing bugs.
    let vk = sk.verifying_key();
    let valid = verify(&bytes, &vk);

    print_receipt_table(&receipt, valid, demo);

    let pub_path = format!("{out_path}.pub");
    for (p, data) in [(&out_path, &bytes[..]), (&pub_path, &vk.to_bytes()[..])] {
        fs::write(p, data).unwrap_or_else(|e| {
            eprintln!("error: cannot write '{p}': {e}");
            process::exit(2);
        });
    }

    println!("\nreceipt saved -> {out_path}  ({RECEIPT_SIZE} bytes)");
    println!("public key    -> {pub_path}  (verify with: aetherproof verify {out_path} --pubkey {pub_path})");
    println!(
        "binary_hash   = 0x{:016X}  (FNV-1a of {} bytes; a checksum, NOT a cryptographic hash)",
        fnv1a(&binary),
        binary.len()
    );
    process::exit(if valid { 0 } else { 1 });
}

// ── self-test ──────────────────────────────────────────────────────────────────

fn cmd_self_test() {
    let sk = dev_signing_key();
    let vk = dev_verifying_key();
    let mut pass = 0u32;
    let mut fail = 0u32;

    macro_rules! check {
        ($name:expr, $cond:expr) => {
            if $cond {
                println!("  PASS  {}", $name);
                pass += 1;
            } else {
                eprintln!("  FAIL  {}", $name);
                fail += 1;
            }
        };
    }

    println!("AetherProof self-test");
    println!("─────────────────────");

    // T1: RECEIPT_SIZE == 128
    check!("T1: RECEIPT_SIZE == 128", RECEIPT_SIZE == 128);

    // T2: generate -> verify
    let r1 = generate(42, b"test_model.onnx", 0xDEAD_CAFE_0000_0001, 7, &sk);
    let b1 = to_bytes(&r1);
    check!("T2: freshly generated receipt verifies", verify(&b1, &vk));

    // T3: round-trip pid/hash/count
    let r2 = from_bytes(&b1).unwrap();
    check!("T3: round-trip pid", r1.pid == r2.pid);
    check!(
        "T3: round-trip binary_hash",
        r1.binary_hash == r2.binary_hash
    );
    check!(
        "T3: round-trip syscall_count",
        r1.syscall_count == r2.syscall_count
    );
    check!("T3: round-trip binary_len", r1.binary_len == r2.binary_len);

    // T4: tamper probe (flip sig byte -> INVALID, original -> VALID)
    check!("T4: tamper probe passes", tamper_probe(&b1, &vk));

    // T5: flip every metadata byte individually
    let mut all_meta_flip_invalid = true;
    for i in 0..64usize {
        let mut t = b1;
        t[i] ^= 0x55;
        if verify(&t, &vk) {
            all_meta_flip_invalid = false;
        }
    }
    check!(
        "T5: flip any metadata byte -> INVALID (64/64)",
        all_meta_flip_invalid
    );

    // T6: flip every sig byte individually
    let mut all_sig_flip_invalid = true;
    for i in 64..128usize {
        let mut t = b1;
        t[i] ^= 0xAA;
        if verify(&t, &vk) {
            all_sig_flip_invalid = false;
        }
    }
    check!(
        "T6: flip any sig byte -> INVALID (64/64)",
        all_sig_flip_invalid
    );

    // T7: wrong signing key does not verify
    let wrong_sk = aetherproof_core::SigningKey::from_bytes(&[0xFFu8; 32]);
    let r3 = generate(1, b"x", 0, 0, &wrong_sk);
    let b3 = to_bytes(&r3);
    check!("T7: wrong key -> INVALID", !verify(&b3, &vk));

    // T8: FNV-1a known vector
    check!(
        "T8: fnv1a('foobar') == known vector",
        fnv1a(b"foobar") == 0x85944171f73967e8
    );

    // T9: different binaries -> different hashes
    let ra = generate(1, b"model_a", 0, 0, &sk);
    let rb = generate(1, b"model_b", 0, 0, &sk);
    check!(
        "T9: distinct binaries -> distinct hashes",
        ra.binary_hash != rb.binary_hash
    );

    // T10: memory_hash field is preserved
    let rh = generate(1, b"m", 0xABCD_1234_5678_CAFE, 0, &sk);
    check!(
        "T10: memory_hash preserved",
        rh.memory_hash == 0xABCD_1234_5678_CAFE
    );

    println!("─────────────────────");
    println!("{pass} passed  {fail} failed");

    if fail == 0 {
        println!("\nAll self-tests pass (run with the public demo key; tests only).");
        process::exit(0);
    } else {
        process::exit(1);
    }
}

// ── bench ──────────────────────────────────────────────────────────────────────

fn cmd_bench(args: &[String]) {
    let count: u64 = args
        .iter()
        .position(|a| a == "--count")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);

    let sk = dev_signing_key();
    let vk = dev_verifying_key();
    let binary = b"benchmark_model_v1.onnx_placeholder_bytes";

    println!("AetherProof bench - {count} receipts");
    println!("─────────────────────────────────────");

    // Generate
    let t0 = Instant::now();
    let mut receipts = Vec::with_capacity(count as usize);
    for i in 0u32..(count as u32) {
        receipts.push(to_bytes(&generate(i, binary, i as u64, i, &sk)));
    }
    let gen_ms = t0.elapsed().as_millis().max(1);
    let gen_rate = count * 1000 / gen_ms as u64;
    println!("generate: {count} receipts in {gen_ms}ms  ->  {gen_rate} receipts/sec");

    // Verify all
    let t1 = Instant::now();
    let mut verified = 0u64;
    for b in &receipts {
        if verify(b, &vk) {
            verified += 1;
        }
    }
    let ver_ms = t1.elapsed().as_millis().max(1);
    let ver_rate = count * 1000 / ver_ms as u64;
    println!("verify:   {count} receipts in {ver_ms}ms  ->  {ver_rate} receipts/sec");
    println!(
        "verified: {verified}/{count} ({:.1}%)",
        verified as f64 / count as f64 * 100.0
    );

    // Tamper all
    let t2 = Instant::now();
    let mut tamper_ok = 0u64;
    for b in &receipts {
        if tamper_probe(b, &vk) {
            tamper_ok += 1;
        }
    }
    let tamp_ms = t2.elapsed().as_millis().max(1);
    println!("tamper:   {count} probes  in {tamp_ms}ms  ->  {tamper_ok}/{count} tampers detected");

    println!("─────────────────────────────────────");
    if verified == count && tamper_ok == count {
        println!("PASS  {verified}/{count} verified  {tamper_ok}/{count} tamper-detected");
    } else {
        eprintln!("FAIL  verification or tamper-detect failed");
        process::exit(1);
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn print_receipt_table(r: &aetherproof_core::Receipt, valid: bool, demo: bool) {
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│  AetherProof Receipt - AI Execution Audit               │");
    println!("├─────────────────────────────────────────────────────────┤");
    println!("│  pid           : {:<38}│", r.pid);
    println!(
        "│  binary_hash   : 0x{:016X}               │",
        r.binary_hash
    );
    println!(
        "│  memory_hash   : 0x{:016X}               │",
        r.memory_hash
    );
    println!("│  syscall_count : {:<38}│", r.syscall_count);
    println!(
        "│  entropy_seed  : 0x{:08X}                           │",
        r.entropy_seed
    );
    println!("│  timestamp_ns  : {:<38}│", r.timestamp_ns);
    println!("│  binary_len    : {:<38}│", r.binary_len);
    print!("│  sig[0..8]     : ");
    for b in &r.sig[0..8] {
        print!("{b:02X}");
    }
    println!("...                          │");
    println!("├─────────────────────────────────────────────────────────┤");
    let verdict = match (valid, demo) {
        (true, false) => "VALID - Ed25519 signature verified",
        (true, true) => "VALID SIGNATURE - DEMO KEY - PROVES NOTHING",
        (false, _) => "INVALID - signature does not match receipt contents",
    };
    println!("│   {verdict:<54}│");
    println!(
        "│   {:<54}│",
        "hashes are FNV-1a-64 checksums, not cryptographic"
    );
    println!("└─────────────────────────────────────────────────────────┘");
}

fn parse_u64_hex_or_dec(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn print_help() {
    println!("AetherProof - signed AI execution receipts (legacy 128-byte format)");
    println!();
    println!("USAGE:");
    println!("  aetherproof verify   <receipt.bin> (--pubkey <file> | --demo)");
    println!("  aetherproof generate --binary <file> (--key <file> | --demo) [--pid N]");
    println!("                       [--memory-hash H] [--syscall-count N] [--out receipt.bin]");
    println!("  aetherproof self-test");
    println!("  aetherproof bench    [--count N]          (default 50000)");
    println!();
    println!("KEYS:");
    println!("  --key     file with a 32-byte Ed25519 seed (e.g. openssl rand 32 > agent.key)");
    println!("  --pubkey  32-byte public key; generate writes it to <out>.pub");
    println!("  --demo    use the PUBLIC built-in key (testing only; proves nothing)");
    println!();
    println!("EXAMPLES:");
    println!("  aetherproof generate --binary model.onnx --key agent.key --pid 1");
    println!("  aetherproof verify receipt.bin --pubkey receipt.bin.pub");
    println!("  aetherproof self-test");
    println!("  aetherproof bench --count 100000");
}
