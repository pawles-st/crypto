use crate::schnorr::Group;
use crypto_bigint::{Uint, Encoding, NonZero};
use list2::{Point, ShortWeierstrassCurve, Serializable, FpElement};
use serde_json::json;

// =============================================================================
//  Macro for Defining Fp Groups (Static Uint sizes)
// =============================================================================

macro_rules! define_fp_group {
    ($name:ident, $limbs:expr, $p_hex:expr, $g_val:expr) => {
        pub struct $name {
            pub g: Uint<$limbs>,
            pub p: Uint<$limbs>,
            pub q: Uint<$limbs>, 
        }

        impl $name {
            pub fn new() -> Self {
                let p_bytes = hex::decode($p_hex.replace(" ", "").replace("\n", "")).expect("Invalid hex for P");
                // Ensure p_bytes fits. 
                let mut padded = [0u8; $limbs * 8];
                let diff = padded.len().saturating_sub(p_bytes.len());
                for (i, b) in p_bytes.iter().enumerate() {
                    if i + diff < padded.len() {
                        padded[i + diff] = *b;
                    }
                }
                let p = Uint::<$limbs>::from_be_bytes(padded);
                
                let g = Uint::<$limbs>::from($g_val as u64);
                
                // Group order q = (p - 1) / 2  (Safe Primes)
                let one = Uint::<$limbs>::ONE;
                let p_minus_1 = p.wrapping_sub(&one);
                let divisor = NonZero::new(Uint::<$limbs>::from(2u64)).unwrap();
                let q = p_minus_1.wrapping_div(&divisor);
                
                Self { g, p, q }
            }

            fn mod_pow(&self, base: &Uint<$limbs>, exp: &Uint<$limbs>) -> Uint<$limbs> {
                let mut res = Uint::<$limbs>::ONE;
                let mut base = *base;
                let p_nz = NonZero::new(self.p).unwrap();
                
                let bits = exp.bits_vartime();
                for i in 0..bits {
                    if exp.bit_vartime(i) {
                         res = res.mul_mod(&base, &p_nz);
                    }
                    base = base.mul_mod(&base, &p_nz);
                }
                res
            }
        }

        impl Group for $name {
            type Element = Uint<$limbs>;
            type Scalar = Uint<$limbs>;

            fn generator(&self) -> Self::Element {
                self.g
            }
            fn order(&self) -> Self::Scalar {
                self.q
            }
            fn scale_gen(&self, s: &Self::Scalar) -> Self::Element {
                self.mod_pow(&self.g, s)
            }
            fn scale_elem(&self, elem: &Self::Element, s: &Self::Scalar) -> Self::Element {
                self.mod_pow(elem, s)
            }
            fn operate(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
                let p_nz = NonZero::new(self.p).unwrap();
                a.mul_mod(b, &p_nz)
            }
            fn encode_element(&self, elem: &Self::Element) -> String {
                let bytes = elem.to_be_bytes();
                hex::encode(bytes)
            }
            fn hash_to_scalar(&self, bytes: &[u8]) -> Self::Scalar {
                let target_len: usize = $limbs * 8;
                let mut padded = [0u8; $limbs * 8]; 
                
                let diff = target_len.saturating_sub(bytes.len());
                for (i, b) in bytes.iter().enumerate() {
                    if i + diff < target_len {
                        padded[i + diff] = *b;
                    }
                }
                let val = Uint::<$limbs>::from_be_bytes(padded);
                
                let nz_q = NonZero::new(self.q).unwrap();
                val.rem(&nz_q)
            }
        }
    };
}

// --- Define Fp Groups ---

// Fp 1024-bit (Oakley Group 2) - 16 Limbs
define_fp_group!(
    FpGroup1024, 
    16, 
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    2
);

// Fp 2048-bit (RFC 3526 Group 14) - 32 Limbs
define_fp_group!(
    FpGroup2048,
    32,
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    2
);

// Fp 3072-bit (RFC 3526 Group 15) - 48 Limbs
define_fp_group!(
    FpGroup3072,
    48,
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    2
);


// =============================================================================
//  Generic EC Group
// =============================================================================

pub struct EcGroup<const L: usize> {
    pub curve: ShortWeierstrassCurve<list2::FpElement>, 
    pub g: Point<list2::FpElement>,
    pub q: Uint<L>,
}

impl<const L: usize> Group for EcGroup<L> 
where Uint<L>: Encoding
{
    type Element = Point<list2::FpElement>;
    type Scalar = Uint<L>;

    fn generator(&self) -> Self::Element {
        self.g.clone()
    }
    fn order(&self) -> Self::Scalar {
        self.q
    }
    fn scale_gen(&self, s: &Self::Scalar) -> Self::Element {
        // We need to convert Scalar Uint<L> to BigInt (Uint<4> or whatever the internal curve uses?)
        // The `list2` curve implementation likely uses a specific BigInt size or is generic.
        // Looking at `list2` usage in `dh.rs`: `ShortWeierstrassCurve<F>`.
        // The `scalar_mul` takes `&BigInt` which was type aliased to `Uint<4>` in `dh.rs`.
        // This is a PROBLEM if the curve logic in `list2` is hardcoded to `Uint<4>`.
        // Let's assume `list2` scalar_mul works with `Uint<4>` (256 bits).
        // For P-192 (192 bits), it fits in `Uint<4>`.
        // For P-224 (224 bits), it fits in `Uint<4>`.
        // For P-256 (256 bits), it fits in `Uint<4>`.
        
        // So we can map `Uint<L>` to `Uint<4>` if L <= 4.
        
        let s_u4 = self.to_uint4(s);
        self.curve.scalar_mul(&self.g, &s_u4)
    }
    fn scale_elem(&self, elem: &Self::Element, s: &Self::Scalar) -> Self::Element {
        let s_u4 = self.to_uint4(s);
        self.curve.scalar_mul(elem, &s_u4)
    }
    fn operate(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        self.curve.add(a, b)
    }
    fn encode_element(&self, elem: &Self::Element) -> String {
        match elem {
            Point::Affine { x, y } => {
                let x_hex = x.serialize("hex"); 
                let y_hex = y.serialize("hex");
                let json_val = json!({
                    "x": x_hex,
                    "y": y_hex
                });
                serde_json::to_string(&json_val).unwrap()
            }
            _ => panic!("Infinity encoding not defined"),
        }
    }
    fn hash_to_scalar(&self, bytes: &[u8]) -> Self::Scalar {
        let target_len: usize = L * 8;
        
        let mut buf = vec![0u8; target_len];
        let diff = target_len.saturating_sub(bytes.len());
        for (i, b) in bytes.iter().enumerate() {
             if i + diff < target_len {
                buf[i + diff] = *b;
            }
        }
        // Uint::from_be_slice is available
        let val = Uint::<L>::from_be_slice(&buf);
        let nz_q = NonZero::new(self.q).unwrap();
        val.rem(&nz_q)
    }
}

impl<const L: usize> EcGroup<L> 
where Uint<L>: Encoding 
{
    fn to_uint4(&self, s: &Uint<L>) -> Uint<4> {
        // Convert Uint<L> to Uint<4>.
        // Since we know L <= 4 for these curves (192, 224, 256), we can pad.
        let bytes = s.to_be_bytes(); 
        let mut padded = [0u8; 32];
        let bytes_ref = bytes.as_ref();
        let diff = 32usize.saturating_sub(bytes_ref.len());
        for (i, b) in bytes_ref.iter().enumerate() {
            if i + diff < 32 {
                padded[i + diff] = *b;
            }
        }
        Uint::<4>::from_be_bytes(padded)
    }
}

impl EcGroup<3> {
    pub fn new_p192() -> Self {
        // P-192
        let p_hex = "fffffffffffffffffffffffffffffffeffffffffffffffff";
        let a_hex = "fffffffffffffffffffffffffffffffefffffffffffffffc";
        let b_hex = "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1";
        let gx_hex = "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012";
        let gy_hex = "07192b95ffc8da78631011ed6b24cdd573f977a11e794811";
        let n_hex = "ffffffffffffffffffffffff99def836146bc9b1b4d22831";

        Self::create(p_hex, a_hex, b_hex, gx_hex, gy_hex, n_hex)
    }
}

impl EcGroup<4> {
    pub fn new_p224() -> Self {
        // P-224
        let p_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001";
        let a_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE";
        let b_hex = "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4";
        let gx_hex = "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21";
        let gy_hex = "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34";
        let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D";

        Self::create(p_hex, a_hex, b_hex, gx_hex, gy_hex, n_hex)
    }

    pub fn new_p256() -> Self {
        // P-256
        let p_hex = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        let a_hex = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
        let b_hex = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
        let gx_hex = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        let gy_hex = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
        let n_hex = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

        Self::create(p_hex, a_hex, b_hex, gx_hex, gy_hex, n_hex)
    }
}

impl<const L: usize> EcGroup<L> {
    fn create(p_hex: &str, a_hex: &str, b_hex: &str, gx_hex: &str, gy_hex: &str, n_hex: &str) -> Self {
        // Internal helper to create the curve from hex strings.
        // We use Uint<4> for the field elements since max is 256-bit (P-256).
        
        let p_val = Self::hex_to_uint4(p_hex);
        let a_val = Self::hex_to_uint4(a_hex);
        let b_val = Self::hex_to_uint4(b_hex);
        let gx_val = Self::hex_to_uint4(gx_hex);
        let gy_val = Self::hex_to_uint4(gy_hex);
        
        // n is Uint<L>
        let n_bytes = hex::decode(n_hex.replace(" ", "")).unwrap();
        let mut padded = vec![0u8; L*8];
        let diff = padded.len().saturating_sub(n_bytes.len());
        for (i, b) in n_bytes.iter().enumerate() {
            if i + diff < padded.len() {
                padded[i + diff] = *b;
            }
        }
        let n = Uint::<L>::from_be_slice(&padded);
        
        // Removed unused p_fp
        
        let a = FpElement::new(a_val, p_val).unwrap();
        let b = FpElement::new(b_val, p_val).unwrap();
        let gx = FpElement::new(gx_val, p_val).unwrap();
        let gy = FpElement::new(gy_val, p_val).unwrap();

        let curve = ShortWeierstrassCurve { a, b };
        let g = Point::Affine { x: gx, y: gy };
        
        Self { curve, g, q: n }
    }    
    fn hex_to_uint4(h: &str) -> Uint<4> {
        let bytes = hex::decode(h.replace(" ", "")).unwrap();
        let mut padded = [0u8; 32];
        let diff = 32usize.saturating_sub(bytes.len());
        for (i, b) in bytes.iter().enumerate() {
            if i + diff < 32 {
                padded[i + diff] = *b;
            }
        }
        Uint::<4>::from_be_bytes(padded)
    }
}