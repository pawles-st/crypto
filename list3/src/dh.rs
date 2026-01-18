use list2::{Point, FieldElement, ShortWeierstrassCurve, BinaryCurve};
use crypto_bigint::{Uint, RandomMod, NonZero};
use crypto_bigint::rand_core::OsRng;
use subtle::ConditionallySelectable;

pub type BigInt = Uint<4>;

// --- Parameter Structures matching Requirements ---

#[derive(Clone, Debug)]
pub enum DhParams<F: FieldElement> {
    Field {
        g: F,
        q: BigInt, 
    },
    Ec {
        a: F,
        b: F,
        g: Point<F>,
        q: BigInt,
    }
}

// --- Generic Diffie-Hellman implementation ---

pub struct DhFieldParams<T> {
    pub g: T,
    pub q: BigInt, 
}

pub struct DhField<T> {
    pub params: DhFieldParams<T>,
}

impl<T: FieldElement> DhField<T> {
    pub fn new(params: DhFieldParams<T>) -> Self {
        Self { params }
    }

    pub fn generate_keypair(&self) -> (BigInt, T) {
        let sk = generate_random_scalar(&self.params.q);
        let pk = self.params.g.pow(&sk);
        (sk, pk)
    }

    pub fn compute_shared_secret(&self, sk: &BigInt, other_pk: &T) -> T {
        other_pk.pow(sk)
    }
}

// --- Curve Traits & Structs ---

pub trait CurveTrait<F> {
    fn scalar_mul(&self, p: &Point<F>, n: &BigInt) -> Point<F>;
}

impl<F: FieldElement + ConditionallySelectable> CurveTrait<F> for ShortWeierstrassCurve<F> {
    fn scalar_mul(&self, p: &Point<F>, n: &BigInt) -> Point<F> {
        ShortWeierstrassCurve::scalar_mul(self, p, n)
    }
}

impl<F: FieldElement + ConditionallySelectable> CurveTrait<F> for BinaryCurve<F> {
    fn scalar_mul(&self, p: &Point<F>, n: &BigInt) -> Point<F> {
        BinaryCurve::scalar_mul(self, p, n)
    }
}

pub struct DhCurveParams<F, C> {
    pub curve: C,
    pub g: Point<F>,
    pub q: BigInt,
}

pub struct DhCurve<F, C> {
    pub params: DhCurveParams<F, C>,
}

impl<F: FieldElement, C: CurveTrait<F>> DhCurve<F, C> {
    pub fn new(params: DhCurveParams<F, C>) -> Self {
        Self { params }
    }

    pub fn generate_keypair(&self) -> (BigInt, Point<F>) {
        let sk = generate_random_scalar(&self.params.q);
        let pk = self.params.curve.scalar_mul(&self.params.g, &sk);
        (sk, pk)
    }

    pub fn compute_shared_secret(&self, sk: &BigInt, other_pk: &Point<F>) -> Point<F> {
        self.params.curve.scalar_mul(other_pk, sk)
    }
}

fn generate_random_scalar(modulus: &BigInt) -> BigInt {
    let mut rng = OsRng;
    let modulus_nz = NonZero::new(*modulus).expect("Modulus must be non-zero");
    BigInt::random_mod(&mut rng, &modulus_nz)
}

#[cfg(test)]
mod tests {
    use super::*;
    use list2::{FpElement, ShortWeierstrassCurve, Point, F2mElement, FpkElement};
    use crypto_bigint::U256;

    #[test]
    fn test_dh_curve_secp256k1() {
        let secp_p_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        let secp_n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let secp_gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let secp_gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

        let p = U256::from_be_hex(secp_p_hex);
        let n = U256::from_be_hex(secp_n_hex);
        let gx = U256::from_be_hex(secp_gx_hex);
        let gy = U256::from_be_hex(secp_gy_hex);
        let a = U256::ZERO;
        let b = U256::from(7u64);

        let a_fp = FpElement::new(a, p).unwrap();
        let b_fp = FpElement::new(b, p).unwrap();
        let gx_fp = FpElement::new(gx, p).unwrap();
        let gy_fp = FpElement::new(gy, p).unwrap();

        let curve = ShortWeierstrassCurve { a: a_fp, b: b_fp };
        let g = Point::Affine { x: gx_fp, y: gy_fp };

        let params = DhCurveParams {
            curve,
            g,
            q: n,
        };

        let dh = DhCurve::new(params);

        let (alice_sk, alice_pk) = dh.generate_keypair();
        let (bob_sk, bob_pk) = dh.generate_keypair();

        let alice_shared = dh.compute_shared_secret(&alice_sk, &bob_pk);
        let bob_shared = dh.compute_shared_secret(&bob_sk, &alice_pk);

        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_dh_params_instantiation() {
        // 1. Fp
        let p = U256::from(23u64);
        let g_val = U256::from(2u64);
        let q = U256::from(11u64);
        let g_fp = FpElement::new(g_val, p).unwrap();
        
        let _fp_params = DhParams::Field { g: g_fp, q };
        
        // 2. F2k
        let poly_bi = U256::from(0b10011u64);
        let g_bi = U256::from(2u64);
        let g_f2m = F2mElement::new(g_bi, poly_bi).unwrap();
        let q_f2m = U256::from(15u64);
        
        let _f2k_params = DhParams::Field { g: g_f2m, q: q_f2m };
        
        // 3. Fpk
        const DEGREE: usize = 2;
        let p_fpk = U256::from(7u64);
        let irre_poly = [U256::from(3u64), U256::ZERO];
        let g_coeffs = [U256::from(1u64), U256::from(1u64)];
        let g_fpk = FpkElement::<DEGREE>::new(g_coeffs, p_fpk, irre_poly).unwrap();
        let q_fpk = U256::from(48u64);
        
        let _fpk_params = DhParams::Field { g: g_fpk, q: q_fpk };
        
        // 4. EC
        let a = FpElement::new(U256::ZERO, p).unwrap();
        let b = FpElement::new(U256::from(7u64), p).unwrap();
        let gx = FpElement::new(U256::ONE, p).unwrap(); // dummy coords
        let gy = FpElement::new(U256::ONE, p).unwrap();
        let g_point = Point::Affine { x: gx, y: gy };
        
        let _ec_params = DhParams::Ec {
            a,
            b,
            g: g_point,
            q,
        };
    }

    #[test]
    fn test_dh_field_fp() {
        // p = 23, q = 11, g = 2
        let p = U256::from(23u64);
        let g_val = U256::from(2u64);
        let q = U256::from(11u64);
        
        let g = FpElement::new(g_val, p).unwrap();
        let params = DhFieldParams { g, q };
        let dh = DhField::new(params);
        
        let (alice_sk, alice_pk) = dh.generate_keypair();
        let (bob_sk, bob_pk) = dh.generate_keypair();
        
        assert_eq!(dh.compute_shared_secret(&alice_sk, &bob_pk), dh.compute_shared_secret(&bob_sk, &alice_pk));
    }

    #[test]
    fn test_dh_field_f2m() {
        use list2::F2mElement;
        // Field F_{2^4} defined by x^4 + x + 1 (19)
        let poly_bi = U256::from(0b10011u64);
        
        // Generator g = x (0b0010)
        // Group order: 2^4 - 1 = 15. 
        let g = F2mElement::new(U256::from(2u64), poly_bi).unwrap();
        let q = U256::from(15u64);

        let params = DhFieldParams { g, q };
        let dh = DhField::new(params);
        let (a_sk, a_pk) = dh.generate_keypair();
        let (b_sk, b_pk) = dh.generate_keypair();
        
        assert_eq!(dh.compute_shared_secret(&a_sk, &b_pk), dh.compute_shared_secret(&b_sk, &a_pk));
    }

    #[test]
    fn test_dh_field_fpk() {
        use list2::FpkElement;
        // F_{p^2} with p=7, irre_poly = x^2 - 3.
        const DEGREE: usize = 2;
        let p = U256::from(7u64);
        let irre_poly = [U256::from(3u64), U256::ZERO];
        
        // Order of F_{p^2}* is p^2 - 1 = 49 - 1 = 48.
        let q = U256::from(48u64);
        
        // g = x + 1 -> coeffs [1, 1]
        let g_coeffs = [U256::from(1u64), U256::from(1u64)];
        let g = FpkElement::<DEGREE>::new(g_coeffs, p, irre_poly).unwrap();

        let params = DhFieldParams { g, q };
        let dh = DhField::new(params);
        let (a_sk, a_pk) = dh.generate_keypair();
        let (b_sk, b_pk) = dh.generate_keypair();
        
        assert_eq!(dh.compute_shared_secret(&a_sk, &b_pk), dh.compute_shared_secret(&b_sk, &a_pk));
    }

    #[test]
    fn test_dh_curve_binary() {
        use list2::{F2mElement, BinaryCurve};
        
        // Field F_{2^4}
        let poly_bi = U256::from(0b10011u64);
        
        // Construct a Binary Curve: y^2 + xy = x^3 + ax^2 + b
        // P = (x, x+1) where x is generator (0b0010)
        let x_elem = F2mElement::new(U256::from(2u64), poly_bi).unwrap();
        let y_elem = F2mElement::new(U256::from(3u64), poly_bi).unwrap();
        
        let a_coeff = F2mElement::new(U256::from(1u64), poly_bi).unwrap(); // a=1
        
        // b = y^2 + xy + x^3 + ax^2
        let x2 = x_elem * x_elem;
        let x3 = x2 * x_elem;
        let y2 = y_elem * y_elem;
        let xy = x_elem * y_elem;
        let ax2 = a_coeff * x2;
        
        let b_coeff = y2 + xy + x3 + ax2;
        
        let curve = BinaryCurve { a: a_coeff, b: b_coeff };
        let g = Point::Affine { x: x_elem, y: y_elem };
        assert!(curve.is_on_curve(&g));
        
        let q = U256::from(16u64); 

        let params = DhCurveParams { curve, g, q };
        let dh = DhCurve::new(params);
        
        let (a_sk, a_pk) = dh.generate_keypair();
        let (b_sk, b_pk) = dh.generate_keypair();
        
        assert_eq!(dh.compute_shared_secret(&a_sk, &b_pk), dh.compute_shared_secret(&b_sk, &a_pk));
    }

    #[test]
    fn test_dh_curve_sw_fpk() {
        use list2::{FpkElement, ShortWeierstrassCurve};
        
        const DEGREE: usize = 2;
        let p = U256::from(23u64); 
        // x^2 - 5 (5 is not quadratic residue mod 23)
        let irre_poly = [U256::from(5u64), U256::ZERO]; 
        
        // Curve: y^2 = x^3 + ax + b
        // Pick P=(1, 1)
        let one_coeffs = [U256::from(1u64), U256::ZERO];
        let one = FpkElement::<DEGREE>::new(one_coeffs, p, irre_poly).unwrap();
        
        let x = one;
        let y = one;
        let a = one;
        
        // b = y^2 - x^3 - ax
        let x2 = x*x;
        let x3 = x2*x;
        let y2 = y*y;
        let ax = a*x;
        let b = y2 - x3 - ax;
        
        let curve = ShortWeierstrassCurve { a, b };
        let g = Point::Affine { x, y };
        assert!(curve.is_on_curve(&g));
        
        let q = U256::from(100u64); // dummy order
        
        let params = DhCurveParams { curve, g, q };
        let dh = DhCurve::new(params);
        
        let (a_sk, a_pk) = dh.generate_keypair();
        let (b_sk, b_pk) = dh.generate_keypair();
        
        assert_eq!(dh.compute_shared_secret(&a_sk, &b_pk), dh.compute_shared_secret(&b_sk, &a_pk));
    }
}
