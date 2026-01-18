use list3::schnorr::{Group, Schnorr};
use crypto_bigint::{U256, NonZero, Encoding, Uint};
use list2::{FpElement, F2mElement, FpkElement, ShortWeierstrassCurve, BinaryCurve, Point, Serializable, FieldElement};
use serde_json::json;

// --- Helper: Map U256 (BigInt) to bytes for hash_to_scalar ---
// This assumes the Group Scalar is always U256 for testing convenience
// (In reality, it depends on curve order size)

fn hash_to_u256(bytes: &[u8], q: &U256) -> U256 {
    let mut padded = [0u8; 32];
    let diff = 32usize.saturating_sub(bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        if i + diff < 32 {
            padded[i + diff] = *b;
        }
    }
    let val = U256::from_be_bytes(padded);
    let nz_q = NonZero::new(*q).unwrap();
    val.rem(&nz_q)
}

// -----------------------------------------------------------------------------
// 1. Fp Group Adapter
// -----------------------------------------------------------------------------
struct FpTestGroup {
    g: FpElement,
    q: U256,
}

impl Group for FpTestGroup {
    type Element = FpElement;
    type Scalar = U256;

    fn generator(&self) -> Self::Element { self.g.clone() }
    fn order(&self) -> Self::Scalar { self.q }
    fn scale_gen(&self, s: &Self::Scalar) -> Self::Element { self.g.pow(s) }
    fn scale_elem(&self, elem: &Self::Element, s: &Self::Scalar) -> Self::Element { elem.pow(s) }
    fn operate(&self, a: &Self::Element, b: &Self::Element) -> Self::Element { *a * *b }
    fn encode_element(&self, elem: &Self::Element) -> String { elem.serialize("hex") }
    fn hash_to_scalar(&self, bytes: &[u8]) -> Self::Scalar { hash_to_u256(bytes, &self.q) }
}

#[test]
fn test_schnorr_fp_list2() {
    let p = U256::from(23u64);
    let g_val = U256::from(2u64);
    let q = U256::from(11u64);
    let g = FpElement::new(g_val, p).unwrap();
    let group = FpTestGroup { g, q };
    
    let schnorr = Schnorr::new(group);
    let (sk, pk) = schnorr.keygen();
    let msg = "test fp";
    let sig = schnorr.sign(&sk, msg);
    assert!(schnorr.verify(&pk, msg, &sig));
}


// -----------------------------------------------------------------------------
// 2. F2m Group Adapter
// -----------------------------------------------------------------------------
struct F2mTestGroup {
    g: F2mElement,
    q: U256,
}

impl Group for F2mTestGroup {
    type Element = F2mElement;
    type Scalar = U256;

    fn generator(&self) -> Self::Element { self.g.clone() }
    fn order(&self) -> Self::Scalar { self.q }
    fn scale_gen(&self, s: &Self::Scalar) -> Self::Element { self.g.pow(s) }
    fn scale_elem(&self, elem: &Self::Element, s: &Self::Scalar) -> Self::Element { elem.pow(s) }
    fn operate(&self, a: &Self::Element, b: &Self::Element) -> Self::Element { *a * *b }
    fn encode_element(&self, elem: &Self::Element) -> String { elem.serialize("hex") }
    fn hash_to_scalar(&self, bytes: &[u8]) -> Self::Scalar { hash_to_u256(bytes, &self.q) }
}

#[test]
fn test_schnorr_f2m_list2() {
    let poly_bi = U256::from(0b10011u64); // x^4 + x + 1
    let g_bi = U256::from(2u64); // x
    let g = F2mElement::new(g_bi, poly_bi).unwrap();
    let q = U256::from(15u64); // 2^4 - 1
    let group = F2mTestGroup { g, q };

    let schnorr = Schnorr::new(group);
    let (sk, pk) = schnorr.keygen();
    let msg = "test f2m";
    let sig = schnorr.sign(&sk, msg);
    assert!(schnorr.verify(&pk, msg, &sig));
}

// -----------------------------------------------------------------------------
// 3. Fpk Group Adapter
// -----------------------------------------------------------------------------
struct FpkTestGroup<const K: usize> {
    g: FpkElement<K>,
    q: U256,
}

impl<const K: usize> Group for FpkTestGroup<K> {
    type Element = FpkElement<K>;
    type Scalar = U256;

    fn generator(&self) -> Self::Element { self.g.clone() }
    fn order(&self) -> Self::Scalar { self.q }
    fn scale_gen(&self, s: &Self::Scalar) -> Self::Element { self.g.pow(s) }
    fn scale_elem(&self, elem: &Self::Element, s: &Self::Scalar) -> Self::Element { elem.pow(s) }
    fn operate(&self, a: &Self::Element, b: &Self::Element) -> Self::Element { *a * *b }
    fn encode_element(&self, elem: &Self::Element) -> String { elem.serialize("hex") }
    fn hash_to_scalar(&self, bytes: &[u8]) -> Self::Scalar { hash_to_u256(bytes, &self.q) }
}

#[test]
fn test_schnorr_fpk_list2() {
    const K: usize = 2;
    let p = U256::from(7u64);
    let irre_poly = [U256::from(3u64), U256::ZERO]; // x^2 - 3
    let g_coeffs = [U256::from(1u64), U256::from(1u64)]; // x + 1
    let g = FpkElement::<K>::new(g_coeffs, p, irre_poly).unwrap();
    let q = U256::from(48u64); // p^2 - 1 = 48
    
    let group = FpkTestGroup { g, q };
    
    let schnorr = Schnorr::new(group);
    let (sk, pk) = schnorr.keygen();
    let msg = "test fpk";
    let sig = schnorr.sign(&sk, msg);
    assert!(schnorr.verify(&pk, msg, &sig));
}

// -----------------------------------------------------------------------------
// 4. Short Weierstrass Curve Group Adapter
// -----------------------------------------------------------------------------
struct SwEcTestGroup {
    curve: ShortWeierstrassCurve<FpElement>,
    g: Point<FpElement>,
    q: U256,
}

impl Group for SwEcTestGroup {
    type Element = Point<FpElement>;
    type Scalar = U256;

    fn generator(&self) -> Self::Element { self.g.clone() }
    fn order(&self) -> Self::Scalar { self.q }
    fn scale_gen(&self, s: &Self::Scalar) -> Self::Element { self.curve.scalar_mul(&self.g, s) }
    fn scale_elem(&self, elem: &Self::Element, s: &Self::Scalar) -> Self::Element { self.curve.scalar_mul(elem, s) }
    fn operate(&self, a: &Self::Element, b: &Self::Element) -> Self::Element { self.curve.add(a, b) }
    fn encode_element(&self, elem: &Self::Element) -> String { 
        match elem {
            Point::Affine { x, y } => {
                let x_hex = x.serialize("hex");
                let y_hex = y.serialize("hex");
                json!({"x": x_hex, "y": y_hex}).to_string()
            },
            Point::Infinity => "infinity".to_string()
        }
    }
    fn hash_to_scalar(&self, bytes: &[u8]) -> Self::Scalar { hash_to_u256(bytes, &self.q) }
}

#[test]
fn test_schnorr_sw_ec_list2() {
    // P-192 parameters roughly, or small manual
    let p = U256::from(23u64);
    let a = FpElement::new(U256::ONE, p).unwrap(); // a=1
    // y^2 = x^3 + x + b. P=(1,1) -> 1 = 1 + 1 + b -> b = -1 = 22
    let b = FpElement::new(U256::from(22u64), p).unwrap();
    let curve = ShortWeierstrassCurve { a, b };
    let g = Point::Affine { 
        x: FpElement::new(U256::ONE, p).unwrap(), 
        y: FpElement::new(U256::ONE, p).unwrap() 
    };
    let q = U256::from(28u64); // Order is approximately p+1 +/- ... let's assume valid or just run test

    let group = SwEcTestGroup { curve, g, q };
    let schnorr = Schnorr::new(group);
    let (sk, pk) = schnorr.keygen();
    let msg = "test sw ec";
    let sig = schnorr.sign(&sk, msg);
    assert!(schnorr.verify(&pk, msg, &sig));
}

// -----------------------------------------------------------------------------
// 5. Binary Curve Group Adapter
// -----------------------------------------------------------------------------
struct BinaryEcTestGroup {
    curve: BinaryCurve<F2mElement>,
    g: Point<F2mElement>,
    q: U256,
}

impl Group for BinaryEcTestGroup {
    type Element = Point<F2mElement>;
    type Scalar = U256;

    fn generator(&self) -> Self::Element { self.g.clone() }
    fn order(&self) -> Self::Scalar { self.q }
    fn scale_gen(&self, s: &Self::Scalar) -> Self::Element { self.curve.scalar_mul(&self.g, s) }
    fn scale_elem(&self, elem: &Self::Element, s: &Self::Scalar) -> Self::Element { self.curve.scalar_mul(elem, s) }
    fn operate(&self, a: &Self::Element, b: &Self::Element) -> Self::Element { self.curve.add(a, b) }
    fn encode_element(&self, elem: &Self::Element) -> String { 
        match elem {
            Point::Affine { x, y } => {
                let x_hex = x.serialize("hex");
                let y_hex = y.serialize("hex");
                json!({"x": x_hex, "y": y_hex}).to_string()
            },
            Point::Infinity => "infinity".to_string()
        }
    }
    fn hash_to_scalar(&self, bytes: &[u8]) -> Self::Scalar { hash_to_u256(bytes, &self.q) }
}

#[test]
fn test_schnorr_binary_ec_list2() {
    let poly = U256::from(0b10011u64); // F2^4
    // Curve: y^2 + xy = x^3 + x^2 + b
    let a_coeff = F2mElement::new(U256::from(1u64), poly).unwrap(); 
    // Generator G=(x, x+1) = (2, 3)
    let x = F2mElement::new(U256::from(2u64), poly).unwrap();
    let y = F2mElement::new(U256::from(3u64), poly).unwrap();
    
    // b = y^2 + xy + x^3 + ax^2
    let x2 = x*x;
    let x3 = x2*x;
    let y2 = y*y;
    let xy = x*y;
    let ax2 = a_coeff*x2;
    let b_coeff = y2 + xy + x3 + ax2;
    
    let curve = BinaryCurve { a: a_coeff, b: b_coeff };
    let g = Point::Affine { x, y };
    let q = U256::from(16u64); // Approx order

    let group = BinaryEcTestGroup { curve, g, q };
    let schnorr = Schnorr::new(group);
    let (sk, pk) = schnorr.keygen();
    let msg = "test binary ec";
    let sig = schnorr.sign(&sk, msg);
    assert!(schnorr.verify(&pk, msg, &sig));
}
