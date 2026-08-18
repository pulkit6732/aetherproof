// AetherProof CLI
// Author: Pulkit Kr Srivastava <pulkitsrivastavae@gmail.com>

//! aetherproof CLI - generate, verify, benchmark, and self-test AetherProof receipts.
//!
//! Commands
//!   verify   <receipt.bin>                       verify a 128-byte receipt
//!   generate --binary <file> [--pid N]            generate + sign a receipt, print + save
//!            [--memory-hash H] [--syscall-count N]
//!            [--out receipt.bin]
//!   self-test                                     run all internal correctness checks
//!   bench    [--count N]                          measure receipts/second (default 50000)

use aetherproof_core::{
    dev_signing_key, dev_verifying_key, fnv1a, from_bytes, generate, tamper_probe, to_bytes,
    verify, RECEIPT_SIZE,
};
use std::{env, fs, process, time::Instant};

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
    if args.is_empty() {
        eprintln!("usage: aetherproof verify <receipt.bin>");
        process::exit(1);
    }

    let path = &args[0];
    let raw = fs::read(path).unwrap_or_else(|e| {
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

    let vk = dev_verifying_key();
    let valid = verify(data, &vk);
    print_receipt_table(&receipt, valid);
    process::exit(if valid { 0 } else { 1 });
}

// ── generate ───────────────────────────────────────────────────────────────────

fn cmd_generate(args: &[String]) {
    let mut binary_path: Option<String> = None;
    let mut pid: u32 = 1;
    let mut memory_hash: u64 = 0;
    let mut syscall_count: u32 = 0;
    let mut out_path: String = "receipt.bin".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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

    let binary = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{path}': {e}");
        process::exit(2);
    });

    let sk = dev_signing_key();
    let receipt = generate(pid, &binary, memory_hash, syscall_count, &sk);
    let bytes = to_bytes(&receipt);

    // Verify immediately to catch signing bugs.
    let vk = dev_verifying_key();
    let valid = verify(&bytes, &vk);

    print_receipt_table(&receipt, valid);

    fs::write(&out_path, bytes).unwrap_or_else(|e| {
        eprintln!("error: cannot write '{out_path}': {e}");
        process::exit(2);
    });

    println!("\nreceipt saved -> {out_path}  ({RECEIPT_SIZE} bytes)");
    println!(
        "binary_hash   = 0x{:016X}  (FNV-1a of {} bytes)",
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
        println!("\nAll tests pass - EU AI Act §13(3)(c) compliant receipt engine verified.");
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

fn print_receipt_table(r: &aetherproof_core::Receipt, valid: bool) {
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
    if valid {
        println!("│   VALID - Ed25519 verified - EU AI Act §13(3)(c)     │");
    } else {
        println!("│   INVALID - signature does not match receipt contents  │");
    }
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
    println!("AetherProof - cryptographic AI execution audit (EU AI Act §13(3)(c))");
    println!();
    println!("USAGE:");
    println!("  aetherproof verify   <receipt.bin>");
    println!("  aetherproof generate --binary <file> [--pid N] [--memory-hash H]");
    println!("                       [--syscall-count N] [--out receipt.bin]");
    println!("  aetherproof self-test");
    println!("  aetherproof bench    [--count N]          (default 50000)");
    println!();
    println!("EXAMPLES:");
    println!("  aetherproof generate --binary model.onnx --pid 1");
    println!("  aetherproof verify receipt.bin");
    println!("  aetherproof self-test");
    println!("  aetherproof bench --count 100000");
}
