use list3::impls::{FpGroup2048, EcGroup};
use list3::schnorr::Group;
use crypto_bigint::{Uint, NonZero, Encoding};
use list2::{Point, Serializable};

fn main() {
    debug_fp2048();
    debug_ecp224();
}

fn debug_fp2048() {
    println!("Debugging Fp-2048...");
    let group = FpGroup2048::new();
    let g = group.generator();
    let q = group.order();
    let p = group.p;

    let g_bytes = Encoding::to_be_bytes(&g);
    println!("g = {}", hex::encode(g_bytes));
    
    // Check g^q mod p
    let g_q = group.scale_gen(&q);
    let g_q_bytes = Encoding::to_be_bytes(&g_q);
    println!("g^q = {}", hex::encode(g_q_bytes));
    
    let one = Uint::<32>::ONE;
    if g_q == one {
        println!("SUCCESS: g^q == 1 mod p");
    } else {
        println!("FAILURE: g^q != 1 mod p");
    }
}

fn debug_ecp224() {
    println!("\nDebugging EC-P224...");
    let group = EcGroup::<4>::new_p224();
    let g = group.generator();
    let n = group.order();
    
    // Check if G is on curve
    let on_curve = group.curve.is_on_curve(&g);
    println!("G is on curve: {}", on_curve);
    
    if let Point::Affine { x, y } = g {
        let x_val = x;
        let y_val = y;
        
        let lhs = y_val * y_val;
        
        let x2 = x_val * x_val;
        let x3 = x2 * x_val;
        let ax = group.curve.a * x_val;
        let rhs = x3 + ax + group.curve.b;
        
        println!("Match x^3+ax+b == y^2: {}", lhs == rhs);
    }

    // Check G*n = Infinity
    let g_n = group.scale_gen(&n);
    let is_identity = match g_n {
        Point::Infinity => true,
        _ => false,
    };
    println!("G*n == Infinity: {}", is_identity);
}
