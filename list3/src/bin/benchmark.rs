use list3::impls::{FpGroup1024, FpGroup2048, FpGroup3072, EcGroup};
use list3::schnorr::{Schnorr, Group};
use std::time::{Instant, Duration};

fn main() {
    println!("Benchmarking Schnorr Signature Scheme across Security Levels\n");

    // --- Level 0: 80-bit (Legacy) ---
    println!("=== Level 0: 80-bit Security (Legacy) ===");
    println!("1. Fp (1024-bit Oakley Group 2)");
    println!("2. EC (P-192)");
    
    let fp1024 = FpGroup1024::new();
    run_benchmark("Fp-1024", fp1024);
    
    let ec192 = EcGroup::<3>::new_p192();
    run_benchmark("EC-P192", ec192);
    
    // --- Level 1: 112-bit ---
    println!("\n=== Level 1: 112-bit Security ===");
    println!("1. Fp (2048-bit RFC 3526 Group 14)");
    println!("2. EC (P-224)");
    
    let fp2048 = FpGroup2048::new();
    run_benchmark("Fp-2048", fp2048);
    
    let ec224 = EcGroup::<4>::new_p224();
    run_benchmark("EC-P224", ec224);

    // --- Level 2: 128-bit ---
    println!("\n=== Level 2: 128-bit Security ===");
    println!("1. Fp (3072-bit RFC 3526 Group 15)");
    println!("2. EC (P-256)");
    
    let fp3072 = FpGroup3072::new();
    run_benchmark("Fp-3072", fp3072);
    
    let ec256 = EcGroup::<4>::new_p256();
    run_benchmark("EC-P256", ec256);
}

fn run_benchmark<G: Group>(name: &str, group: G) {
    let schnorr = Schnorr::new(group);
    let msg = "Hello, Schnorr!";
    
    // Determine iterations based on complexity to keep benchmark fast but accurate
    // Fp is slow, EC is fast.
    let iterations = if name.contains("Fp") { 5 } else { 50 };
    
    println!("\n--- {} ({} iters) ---", name, iterations);
    
    // KeyGen
    let mut keygen_times = Vec::new();
    let mut keys = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let keypair = schnorr.keygen();
        keygen_times.push(start.elapsed());
        keys.push(keypair);
    }
    
    // Sign
    let mut sign_times = Vec::new();
    let mut sigs = Vec::new();
    for (sk, _) in &keys {
        let start = Instant::now();
        let sig = schnorr.sign(sk, msg);
        sign_times.push(start.elapsed());
        sigs.push(sig);
    }
    
    // Verify
    let mut verify_times = Vec::new();
    for ((_, pk), sig) in keys.iter().zip(sigs.iter()) {
        let start = Instant::now();
        let valid = schnorr.verify(pk, msg, sig);
        verify_times.push(start.elapsed());
        if !valid {
            println!("!! Verification Failed for {} !!", name);
        }
    }
    
    print_stats("KeyGen", &keygen_times);
    print_stats("Sign  ", &sign_times);
    print_stats("Verify", &verify_times);
}

fn print_stats(op: &str, times: &[Duration]) {
    let total: Duration = times.iter().sum();
    let avg = total / times.len() as u32;
    println!("{}: {:?}", op, avg);
}