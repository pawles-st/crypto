use crypto_bigint::{NonZero, Uint, Zero as BigIntZero};
use std::fmt::{self, Debug, Display};
use std::ops::{Add, Div, Mul, Neg, Sub};
use subtle::{Choice, ConditionallySelectable};

const LIMBS: usize = 4;
pub type BigInt = Uint<LIMBS>;

pub fn to_decimal(n: &BigInt) -> String {
    let mut temp = *n;
    if temp == BigInt::ZERO {
        return "0".to_string();
    }

    let mut parts = Vec::new();
    // 10^19 is the largest power of 10 that fits in u64
    const CHUNK_SIZE: u64 = 10_000_000_000_000_000_000;
    let chunk_big = NonZero::new(BigInt::from(CHUNK_SIZE)).unwrap();

    while temp != BigInt::ZERO {
        let r = temp.rem(&chunk_big);
        temp = temp.div(&chunk_big);
        
        // Convert remainder (which is < 10^19) to u64.
        let bytes = r.to_le_bytes();
        let val = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        parts.push(val);
    }

    let mut s = String::new();
    let mut iter = parts.into_iter().rev();
    
    if let Some(first) = iter.next() {
        s.push_str(&first.to_string());
    }
    
    for part in iter {
        s.push_str(&format!("{:019}", part));
    }
    s
}

pub trait FieldElement:
    Clone
    + Copy
    + PartialEq
    + Debug
    + Display
    + Sized
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Option<Self>>
    + Neg<Output = Self>
{
    fn inv(&self) -> Option<Self>;
    fn pow(&self, exp: &BigInt) -> Self;
    fn one(&self) -> Self;
    fn zero(&self) -> Self;
    fn is_zero(&self) -> Choice;
}

pub trait Serializable {
    fn serialize(&self, format: &str) -> String;
    fn to_bytes(&self) -> Vec<u8>;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct F2mElement {
    pub bits: BigInt,
    pub reduction_poly: NonZero<BigInt>,
}

impl F2mElement {
    pub fn new(bits: BigInt, reduction_poly: BigInt) -> Option<Self> {
        let nz_poly = NonZero::new(reduction_poly);
        if bool::from(nz_poly.is_some()) {
            let nz_poly = nz_poly.unwrap();
            let reduced_bits = Self::poly_rem(bits, &nz_poly);
            Some(F2mElement {
                bits: reduced_bits,
                reduction_poly: nz_poly,
            })
        } else {
            None
        }
    }

    fn poly_rem(mut num: BigInt, den: &NonZero<BigInt>) -> BigInt {
        let den_val = den.get();
        let den_bits = den_val.bits_vartime();
        if den_bits == 0 { return num; }
        let degree = den_bits - 1;

        for i in (degree..BigInt::BITS).rev() {
            let bit_is_set = num.bit(i);
            let shift = i - degree;
            let shifted_den = den_val.shl_vartime(shift);
            let xored = num ^ shifted_den;
            num = BigInt::conditional_select(&num, &xored, bit_is_set.into());
        }
        num
    }

    fn clmul(&self, other: &Self) -> BigInt {
        let mut mul = other.bits;
        let mut res = BigInt::ZERO;
        let mut term = self.bits;
        let mod_poly = self.reduction_poly.get();

        // The degree of the field
        let degree = mod_poly.bits().saturating_sub(1);

        for _ in 0..degree {
            let lsb_is_one = mul.bit(0);
            res = BigInt::conditional_select(&res, &(res ^ term), lsb_is_one.into());

            let overflows = term.bit(degree - 1);
            term = term.shl(1);
            term = BigInt::conditional_select(&term, &(term ^ mod_poly), overflows.into());

            mul = mul.shr(1);
        }
        res
    }
}

impl ConditionallySelectable for F2mElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F2mElement {
            bits: BigInt::conditional_select(&a.bits, &b.bits, choice),
            reduction_poly: a.reduction_poly,
        }
    }
}

impl Display for F2mElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitString(0x{})", hex::encode(self.bits.to_be_bytes()))
    }
}

impl Add for F2mElement {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        assert_eq!(self.reduction_poly, other.reduction_poly, "Cannot add elements from different fields.");
        F2mElement {
            bits: self.bits ^ other.bits,
            reduction_poly: self.reduction_poly,
        }
    }
}

impl Sub for F2mElement {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        assert_eq!(self.reduction_poly, other.reduction_poly, "Cannot subtract elements from different fields.");
        self + other
    }
}

impl Mul for F2mElement {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        assert_eq!(self.reduction_poly, other.reduction_poly, "Cannot multiply elements from different fields.");
        F2mElement {
            bits: Self::poly_rem(self.clmul(&other), &self.reduction_poly),
            reduction_poly: self.reduction_poly,
        }
    }
}

impl Div for F2mElement {
    type Output = Option<Self>;
    fn div(self, other: Self) -> Option<Self> {
        other.inv().map(|inv| self * inv)
    }
}

impl Neg for F2mElement {
    type Output = Self;
    fn neg(self) -> Self {
        self
    }
}

impl FieldElement for F2mElement {
    fn inv(&self) -> Option<Self> {
        if bool::from(self.is_zero()) {
            return None;
        }
        let m = self.reduction_poly.get().bits_vartime() - 1;
        let mut exp = BigInt::ZERO;
        let one = BigInt::ONE;
        for i in 1..m {
            let bit = one.shl_vartime(i);
            exp = exp | bit;
        }
        Some(self.pow(&exp))
    }

    fn pow(&self, exp: &BigInt) -> Self {
        let mut res = self.one();
        let mut base = *self;
        for i in 0..BigInt::BITS {
            let bit_is_one = exp.bit(i as u32);
            let prod = res * base;
            res = Self::conditional_select(&res, &prod, bit_is_one.into());
            base = base * base;
        }
        res
    }

    fn one(&self) -> Self {
        F2mElement {
            bits: BigInt::ONE,
            reduction_poly: self.reduction_poly,
        }
    }

    fn zero(&self) -> Self {
        F2mElement {
            bits: BigIntZero::zero(),
            reduction_poly: self.reduction_poly,
        }
    }

    fn is_zero(&self) -> Choice {
        self.bits.is_zero()
    }
}

impl Serializable for F2mElement {
    fn serialize(&self, format: &str) -> String {
        match format {
            "hex" => hex::encode(self.bits.to_be_bytes()),
            "base10" => to_decimal(&self.bits),
            "base64" => {
                use base64::{engine::general_purpose, Engine as _};
                general_purpose::STANDARD.encode(self.to_bytes())
            }
            _ => "Unknown Format".to_string(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bits.to_be_bytes().to_vec()
    }
}
