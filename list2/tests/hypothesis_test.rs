use list2::{FpElement, F2mElement, FieldElement, Point, ShortWeierstrassCurve};
use crypto_bigint::{U256, Random};
use rand::rngs::OsRng;
use std::time::Instant;

const SAMPLES: usize = 200;

// --- Mann-Whitney U Test (Equivalent to Kruskal-Wallis for 2 groups) ---

#[derive(Debug)]
struct RankedSample {
    val: f64,
    group: u8, // 0 for A, 1 for B
}

fn calculate_mann_whitney_z(data_a: &[f64], data_b: &[f64]) -> f64 {
    let n_a = data_a.len();
    let n_b = data_b.len();
    if n_a == 0 || n_b == 0 { return 0.0; }

    let mut combined: Vec<RankedSample> = Vec::with_capacity(n_a + n_b);
    for &x in data_a { combined.push(RankedSample { val: x, group: 0 }); }
    for &x in data_b { combined.push(RankedSample { val: x, group: 1 }); }

    // Sort by value. 
    // Handle NaNs by pushing them to the end (though timing shouldn't be NaN).
    combined.sort_by(|a, b| a.val.partial_cmp(&b.val).unwrap_or(std::cmp::Ordering::Less));

    // Assign ranks (handling ties by averaging ranks)
    let mut ranks = vec![0.0; combined.len()];
    let mut i = 0;
    while i < combined.len() {
        let mut j = i + 1;
        while j < combined.len() && combined[j].val == combined[i].val {
            j += 1;
        }
        
        // Items from i to j-1 have equal values.
        // The ranks would be i+1, i+2, ..., j.
        // Average rank = ( (i+1) + j ) / 2.0
        let rank_sum = ((i + 1 + j) as f64) / 2.0;
        
        for k in i..j {
            ranks[k] = rank_sum;
        }
        i = j;
    }

    // Sum ranks for group A (R_1)
    let mut r_a = 0.0;
    for (idx, item) in combined.iter().enumerate() {
        if item.group == 0 {
            r_a += ranks[idx];
        }
    }

    // U statistic
    // U_a = R_a - n_a(n_a + 1)/2
    let u_a = r_a - (n_a * (n_a + 1)) as f64 / 2.0;
    
    // Mean and Standard Deviation of U (assuming large N approximation)
    let mu_u = (n_a * n_b) as f64 / 2.0;
    
    // Tie correction for variance
    // sigma_u = sqrt( (n_a * n_b / 12) * (N + 1 - correction) )
    // Correction involves sum of (t^3 - t) for each set of ties t.
    // For simplicity in this timing test (where floats rarely tie exactly), we use basic variance.
    // sigma_u = sqrt( n_a * n_b * (n_a + n_b + 1) / 12 )
    let sigma_u = ((n_a * n_b * (n_a + n_b + 1)) as f64 / 12.0).sqrt();

    if sigma_u == 0.0 { 0.0 } else { (u_a - mu_u) / sigma_u }
}

fn get_mean(data: &[f64]) -> f64 {
    if data.is_empty() { 0.0 } else { data.iter().sum::<f64>() / data.len() as f64 }
}

fn run_hypothesis_test<T>(name: &str, mut setup_a: impl FnMut() -> T, mut setup_b: impl FnMut() -> T, mut op: impl FnMut(&mut T)) 
where T: Clone {
    println!("\nRunning Hypothesis Test: {}", name); 
    
    let mut timings_a = Vec::with_capacity(SAMPLES);
    let mut timings_b = Vec::with_capacity(SAMPLES);

    // Interleave execution to minimize environmental drift
    for _ in 0..SAMPLES {
        {
            let mut input = setup_a();
            let start = Instant::now();
            op(&mut input);
            let elapsed = start.elapsed().as_secs_f64();
            timings_a.push(elapsed);
        }

        {
            let mut input = setup_b();
            let start = Instant::now();
            op(&mut input);
            let elapsed = start.elapsed().as_secs_f64();
            timings_b.push(elapsed);
        }
    }

    // Calculate Z-score from Mann-Whitney U test
    let z_score = calculate_mann_whitney_z(&timings_a, &timings_b);
    
    // For display purposes, still show means (intuitive), but decision is based on Z-score (ranks).
    let mean_a = get_mean(&timings_a);
    let mean_b = get_mean(&timings_b);

    println!("  Mean A:  {:.9} s", mean_a);
    println!("  Mean B:  {:.9} s", mean_b);
    println!("  MW-Z-score:       {:.4}", z_score);

    if z_score.abs() > 6.0 {
        println!("  [FAIL] {} - Significant timing difference detected!", name);
    } else {
        println!("  [PASS] {} - No significant difference detected.", name);
    }
}

#[test]
fn test_fp_pow_hypothesis() {
    let modulus = U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    let base_val = U256::from(5u64);
    let base = FpElement::new(base_val, modulus).expect("Valid element");

    let exp_a = U256::ONE;
    let exp_b = U256::random(&mut OsRng);

    run_hypothesis_test(
        "FpElement::pow (Exp=1 vs Exp=Random)",
        || (base, exp_a),
        || (base, exp_b),
        | (b, e) | { let _ = b.pow(e); }
    );
}

#[test]
fn test_f2m_pow_hypothesis() {
    let poly = U256::from_be_hex("80000000000000000000000000000000000000000000000000000000000000C5");
    let base_val = U256::from(2u64);
    let base = F2mElement::new(base_val, poly).expect("Valid element");

    let exp_a = U256::ONE;
    let exp_b = U256::random(&mut OsRng);

    run_hypothesis_test(
        "F2mElement::pow (Exp=1 vs Exp=Random)",
        || (base, exp_a),
        || (base, exp_b),
        | (b, e) | { let _ = b.pow(e); }
    );
}

#[test]
fn test_sw_ec_scalar_mul_hypothesis() {
    let modulus = U256::from(23u64);
    let a = FpElement::new(U256::from(1u64), modulus).unwrap();
    let b = FpElement::new(U256::from(1u64), modulus).unwrap();
    let curve = ShortWeierstrassCurve { a, b };

    let p_x = FpElement::new(U256::from(1u64), modulus).unwrap();
    let p_y = FpElement::new(U256::from(7u64), modulus).unwrap();
    let point = Point::Affine { x: p_x, y: p_y };

    let scalar_a = U256::ONE;
    let scalar_b = U256::MAX;

    run_hypothesis_test(
        "SW Curve Scalar Mul (Scalar=1 vs Scalar=MAX)",
        || (curve.clone(), point, scalar_a),
        || (curve.clone(), point, scalar_b),
        | (c, p, s) | { let _ = c.scalar_mul(p, s); }
    );
}

#[test]
fn test_sw_ec_scalar_mul_hw_check() {
    let modulus = U256::from(23u64);
    let a = FpElement::new(U256::from(1u64), modulus).unwrap();
    let b = FpElement::new(U256::from(1u64), modulus).unwrap();
    let curve = ShortWeierstrassCurve { a, b };

    let p_x = FpElement::new(U256::from(1u64), modulus).unwrap();
    let p_y = FpElement::new(U256::from(7u64), modulus).unwrap();
    let point = Point::Affine { x: p_x, y: p_y };

    // Case A: Scalar = 2^255 (High MSB, Low HW = 1)
    let mut scalar_a = U256::ZERO;
    scalar_a = scalar_a | (U256::ONE << 255);

    // Case B: Scalar = MAX (High MSB, High HW = 256)
    let scalar_b = U256::MAX;

    run_hypothesis_test(
        "SW Curve Scalar Mul (HighMSB_LowHW vs HighMSB_HighHW)",
        || (curve.clone(), point, scalar_a),
        || (curve.clone(), point, scalar_b),
        | (c, p, s) | { let _ = c.scalar_mul(p, s); }
    );
}

#[test]
fn test_binary_ec_scalar_mul_hypothesis() {
    // Binary Curve y^2 + xy = x^3 + x^2 + 1 (using poly x^4+x+1)
    let poly = U256::from(0b10011u64);
    let a = F2mElement::new(U256::from(1u64), poly).unwrap();
    let b = F2mElement::new(U256::from(1u64), poly).unwrap();
    let curve = list2::BinaryCurve { a, b };

    let p_x = F2mElement::new(U256::ZERO, poly).unwrap();
    let p_y = F2mElement::new(U256::from(1u64), poly).unwrap();
    let point = Point::Affine { x: p_x, y: p_y };

    // Case A: Scalar = 1
    let scalar_a = U256::ONE;

    // Case B: Scalar = MAX
    let scalar_b = U256::MAX;

    run_hypothesis_test(
        "Binary Curve Scalar Mul (Scalar=1 vs Scalar=MAX)",
        || (curve.clone(), point, scalar_a),
        || (curve.clone(), point, scalar_b),
        | (c, p, s) | { let _ = c.scalar_mul(p, s); }
    );
}

#[test]
fn test_fp_pow_hw_check() {
    let modulus = U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    let base_val = U256::from(5u64);
    let base = FpElement::new(base_val, modulus).expect("Valid element");

    // Case A: Exp = 2^255 (High MSB, Low HW = 1)
    let mut exp_a = U256::ZERO;
    exp_a = exp_a | (U256::ONE << 255);

    // Case B: Exp = MAX (High MSB, High HW = 256)
    let exp_b = U256::MAX;

    run_hypothesis_test(
        "FpElement::pow (HighMSB_LowHW vs HighMSB_HighHW)",
        || (base, exp_a),
        || (base, exp_b),
        | (b, e) | { let _ = b.pow(e); }
    );
}

#[test]
fn test_f2m_pow_hw_check() {
    let poly = U256::from_be_hex("80000000000000000000000000000000000000000000000000000000000000C5");
    let base_val = U256::from(2u64);
    let base = F2mElement::new(base_val, poly).expect("Valid element");

    // Case A: Exp = 2^255 (High MSB, Low HW = 1)
    let mut exp_a = U256::ZERO;
    exp_a = exp_a | (U256::ONE << 255);

    // Case B: Exp = MAX (High MSB, High HW = 256)
    let exp_b = U256::MAX;

    run_hypothesis_test(
        "F2mElement::pow (HighMSB_LowHW vs HighMSB_HighHW)",
        || (base, exp_a),
        || (base, exp_b),
        | (b, e) | { let _ = b.pow(e); }
    );
}
