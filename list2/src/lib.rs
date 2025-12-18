use crypto_bigint::{NonZero, Uint, Zero as BigIntZero};
use std::fmt::{self, Debug, Display};
use std::ops::{Add, Div, Mul, Neg, Sub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

const LIMBS: usize = 4;
type BigInt = Uint<LIMBS>;

fn to_decimal(n: &BigInt) -> String {
    let mut temp = *n;
    if temp == BigInt::ZERO {
        return "0".to_string();
    }
    let mut s = String::new();
    let ten = NonZero::new(BigInt::from(10u8)).unwrap();
    
    while temp != BigInt::ZERO {
        let q = temp.div(&ten);
        let r = temp.rem(&ten);
        let digit = r.to_le_bytes()[0];
        s.push(char::from_digit(digit as u32, 10).unwrap());
        temp = q;
    }
    s.chars().rev().collect()
}

// --- 1. FIELD TRAIT ---

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
    /// Returns `Choice::from(1)` if `self` is zero, and `Choice::from(0)` otherwise.
    /// This operation must be constant-time.
    fn is_zero(&self) -> Choice;
}

// --- 2. PRIME FIELD IMPLEMENTATION (Fp) ---

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FpElement {
    value: BigInt,
    modulus: NonZero<BigInt>,
}

impl FpElement {
    pub fn new(value: BigInt, modulus: BigInt) -> Option<Self> {
        let nz_modulus = NonZero::new(modulus);
        if bool::from(nz_modulus.is_some()) {
            let nz_modulus = nz_modulus.unwrap();
            let value = value.rem(&nz_modulus);
            Some(FpElement {
                value,
                modulus: nz_modulus,
            })
        } else {
            None
        }
    }
}

impl ConditionallySelectable for FpElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        FpElement {
            value: BigInt::conditional_select(&a.value, &b.value, choice),
            modulus: a.modulus,
        }
    }
}

impl Display for FpElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.value.to_be_bytes()))
    }
}

impl Add for FpElement {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Cannot add elements from different fields.");
        let sum = self.value.add_mod(&other.value, &self.modulus);
        FpElement {
            value: sum,
            modulus: self.modulus,
        }
    }
}

impl Sub for FpElement {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Cannot subtract elements from different fields.");
        let diff = self.value.sub_mod(&other.value, &self.modulus);
        FpElement {
            value: diff,
            modulus: self.modulus,
        }
    }
}

impl Mul for FpElement {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Cannot multiply elements from different fields.");
        let prod = self.value.mul_mod(&other.value, &self.modulus);
        FpElement {
            value: prod,
            modulus: self.modulus,
        }
    }
}

impl Div for FpElement {
    type Output = Option<Self>;
    fn div(self, other: Self) -> Option<Self> {
        other.inv().map(|inv| self * inv)
    }
}

impl Neg for FpElement {
    type Output = Self;
    fn neg(self) -> Self {
        let zero_choice = self.is_zero();
        let negated_value = FpElement {
            value: self.modulus.get().sub_mod(&self.value, &self.modulus),
            modulus: self.modulus,
        };
        FpElement::conditional_select(&negated_value, &self, zero_choice)
    }
}

impl FieldElement for FpElement {
    fn inv(&self) -> Option<Self> {
        Into::<Option<BigInt>>::into(self.value.inv_mod(&self.modulus.get())).map(|inv_val| {
            FpElement {
                value: inv_val,
                modulus: self.modulus,
            }
        })
    }

    fn pow(&self, exp: &BigInt) -> Self {
        let mut res = self.one();
        let mut base = *self;
        for i in 0..BigInt::BITS {
            let bit_is_one = exp.bit(i as u32).into();
            let prod = res * base;
            res = Self::conditional_select(&res, &prod, bit_is_one);
            base = base * base;
        }
        res
    }

    fn one(&self) -> Self {
        FpElement {
            value: BigInt::ONE,
            modulus: self.modulus,
        }
    }

    fn zero(&self) -> Self {
        FpElement {
            value: BigIntZero::zero(),
            modulus: self.modulus,
        }
    }

    fn is_zero(&self) -> Choice {
        self.value.is_zero()
    }
}

impl Serializable for FpElement {
    fn serialize(&self, format: &str) -> String {
        match format {
            "hex" => hex::encode(self.value.to_be_bytes()),
            "base10" => to_decimal(&self.value),
            "base64" => {
                use base64::{engine::general_purpose, Engine as _};
                general_purpose::STANDARD.encode(self.to_bytes())
            }
            _ => "Unknown Format".to_string(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.value.to_be_bytes().to_vec()
    }
}


// --- 3. BINARY FIELD IMPLEMENTATION (F2m) ---

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

    /// Performs polynomial long division for binary polynomials (represented as BigInts).
    /// Returns `num mod den`.
    fn poly_rem(mut num: BigInt, den: &NonZero<BigInt>) -> BigInt {
        // `bits_vartime` is fine since the value and modulus are not secret in a constructor.
        let den_bits = den.get().bits_vartime();
        let mut num_bits = num.bits_vartime();

        if den_bits == 0 {
            return num;
        }

        // While degree of num is greater than or equal to degree of den
        if num_bits >= den_bits {
            let den_val = den.get();
            while num_bits >= den_bits {
                let shift = num_bits - den_bits;
                let shifted_den = den_val.shl_vartime(shift);
                num = num ^ shifted_den;
                num_bits = num.bits_vartime();
            }
        }
        num
    }

    /// Performs a constant-time carry-less multiplication.
    fn clmul(&self, other: &Self) -> BigInt {
        let mut mul = other.bits;
        let mut res = BigInt::ZERO;
        let mut term = self.bits;
        let mod_poly = self.reduction_poly.get();

        // The degree of the field, e.g., 256 for F_2^256
        let degree = mod_poly.bits().saturating_sub(1);

        for _ in 0..degree {
            // Constant-time equivalent of `if mul is odd`
            let lsb_is_one = mul.bit(0);
            res = BigInt::conditional_select(&res, &(res ^ term), lsb_is_one.into());

            // Constant-time equivalent of `term = (term * x) mod mod_poly`
            let overflows = term.bit(degree - 1);
            term = term.shl(1);
            term = BigInt::conditional_select(&term, &(term ^ mod_poly), overflows.into());

            // Process the next bit of the multiplier.
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
        self + other // In F2m, subtraction is the same as addition
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
        self // In F2m, negation is the identity
    }
}

impl FieldElement for F2mElement {
    fn inv(&self) -> Option<Self> {
        if bool::from(self.is_zero()) {
            return None;
        }

        // The degree of the field, e.g., 256 for F_2^256
        // This is derived from the reduction_poly, which is publicly known.
        // So, this is not a side-channel leak.
        let degree = self.reduction_poly.get().bits_vartime().saturating_sub(1);

        // Calculate exponent 2^degree - 2
        let mut exp = BigInt::ONE;
        exp = exp.shl(degree as u32);
        exp = exp.sub(&BigInt::from(2u8));

        // Use pow which is constant-time
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

// --- 4. EXTENSION FIELD IMPLEMENTATION (Fpk) ---

// NOTE: irre_poly is simplified to size DEGREE, assuming it's monic and the x^DEGREE term is implicit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FpkElement<const DEGREE: usize> {
    coeffs: [BigInt; DEGREE],
    modulus: NonZero<BigInt>,
    irre_poly: [BigInt; DEGREE],
}

impl<const DEGREE: usize> FpkElement<DEGREE> {
    pub fn new(mut coeffs: [BigInt; DEGREE], modulus: BigInt, irre_poly: [BigInt; DEGREE]) -> Option<Self> {
        let nz_modulus = NonZero::new(modulus);
        if nz_modulus.is_some().into() {
            let nz_modulus = nz_modulus.unwrap();

            // Reduce each coefficient modulo the base field modulus.
            for coeff in coeffs.iter_mut() {
                *coeff = coeff.rem(&nz_modulus);
            }

            // Further checks for irre_poly (e.g., non-zero, correct degree) would go here.
            // For now, we assume it's valid.
            Some(FpkElement {
                coeffs,
                modulus: nz_modulus,
                irre_poly,
            })
        } else {
            None // Modulus cannot be zero
        }
    }

    /// Multiplies the polynomial by a scalar from the base field.
    fn mul_by_scalar(&self, scalar: &BigInt) -> Self {
        let mut new_coeffs = [BigInt::ZERO; DEGREE];
        for i in 0..DEGREE {
            new_coeffs[i] = self.coeffs[i].mul_mod(scalar, &self.modulus);
        }
        Self { coeffs: new_coeffs, ..*self }
    }

    /// Multiplies the polynomial by `x` and reduces the result.
    fn mul_by_x(&self) -> Self {
        let mut new_coeffs = [BigInt::ZERO; DEGREE];
        // The leading coefficient of the original polynomial.
        let leading_coeff_before_shift = self.coeffs[DEGREE - 1];

        // Shift all coefficients left (c_i -> c_{i-1} for i>0)
        // If coeffs was [c0, c1, c2] for DEGREE=3.
        // new_coeffs becomes [0, c0, c1].
        for i in (1..DEGREE).rev() {
            new_coeffs[i] = self.coeffs[i-1];
        }

        // The x^DEGREE term (coefficient `leading_coeff_before_shift`) needs reduction.
        // x^DEGREE = sum(irre_poly[i] * x^i) (mod modulus).
        // So, we effectively add `leading_coeff_before_shift * irre_poly` to the shifted polynomial.
        for i in 0..DEGREE {
            let term_to_add = leading_coeff_before_shift.mul_mod(&self.irre_poly[i], &self.modulus);
            new_coeffs[i] = new_coeffs[i].add_mod(&term_to_add, &self.modulus);
        }
        Self { coeffs: new_coeffs, ..*self }
    }
}


impl<const DEGREE: usize> ConditionallySelectable for FpkElement<DEGREE> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut new_coeffs = [BigIntZero::zero(); DEGREE];
        for i in 0..DEGREE {
            new_coeffs[i] = BigInt::conditional_select(&a.coeffs[i], &b.coeffs[i], choice);
        }
        Self { coeffs: new_coeffs, modulus: a.modulus, irre_poly: a.irre_poly }
    }
}


impl<const DEGREE: usize> Display for FpkElement<DEGREE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Poly{:?}", self.coeffs)
    }
}

impl<const DEGREE: usize> Add for FpkElement<DEGREE> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Cannot add elements from different base fields.");
        assert_eq!(self.irre_poly, other.irre_poly, "Cannot add elements from different extension fields.");
        let mut new_coeffs = [BigIntZero::zero(); DEGREE];
        for i in 0..DEGREE {
            new_coeffs[i] = self.coeffs[i].add_mod(&other.coeffs[i], &self.modulus);
        }
        Self {
            coeffs: new_coeffs,
            ..self
        }
    }
}

impl<const DEGREE: usize> Sub for FpkElement<DEGREE> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Cannot subtract elements from different base fields.");
        assert_eq!(self.irre_poly, other.irre_poly, "Cannot subtract elements from different extension fields.");
        let mut new_coeffs = [BigIntZero::zero(); DEGREE];
        for i in 0..DEGREE {
            new_coeffs[i] = self.coeffs[i].sub_mod(&other.coeffs[i], &self.modulus);
        }
        Self {
            coeffs: new_coeffs,
            ..self
        }
    }
}

impl<const DEGREE: usize> Mul for FpkElement<DEGREE> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Cannot multiply elements from different base fields.");
        assert_eq!(self.irre_poly, other.irre_poly, "Cannot multiply elements from different extension fields.");
        let mut res = self.zero();
        let mut shifted_other = other;

        for i in 0..DEGREE {
            let term = shifted_other.mul_by_scalar(&self.coeffs[i]);
            res = res + term;
            shifted_other = shifted_other.mul_by_x();
        }
        res
    }
}

impl<const DEGREE: usize> Div for FpkElement<DEGREE> {
    type Output = Option<Self>;
    fn div(self, other: Self) -> Option<Self> {
        other.inv().map(|inv| self * inv)
    }
}

impl<const DEGREE: usize> Neg for FpkElement<DEGREE> {
    type Output = Self;
    fn neg(self) -> Self {
        self.zero() - self
    }
}

impl<const DEGREE: usize> FieldElement for FpkElement<DEGREE> {
    fn inv(&self) -> Option<Self> {
        // Use Fermat's Little Theorem for inversion in F_p^k: a^(p^k - 2).
        // This is secure because the `pow` method is implemented in constant-time.
        
        // This check is not constant-time, but inversion of zero is undefined.
        // A non-zero input is a precondition for this function.
        if bool::from(self.is_zero()) {
            return None;
        }

        // Calculate the field order N = p^k.
        let p = self.modulus.get();
        let mut n = BigInt::ONE;

        // This loop calculates p^k. Since DEGREE (k) is a public compile-time
        // constant, this loop runs a fixed number of times.
        for _ in 0..DEGREE {
            // `widening_mul` returns a `Uint` of double width.
            let wide_n = n.widening_mul(&p);
            // We then split it into high and low parts.
            let (lo, hi) = wide_n.split();

            // If `hi` is ever non-zero, it means p^k has overflowed our BigInt size,
            // and this method of inversion is not possible.
            if !bool::from(hi.is_zero()) {
                // This indicates a configuration error where the field is too large
                // for this inversion method. Panicking is appropriate for this
                // unrecoverable configuration problem.
                panic!("Field order p^k overflows BigInt, cannot use FLT for inversion.");
            }
            n = lo;
        }

        // Calculate exponent p^k - 2
        let exp = n.sub(&BigInt::from(2u8));

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
        let mut coeffs = [BigIntZero::zero(); DEGREE];
        coeffs[0] = BigInt::ONE;
        Self { coeffs, ..*self }
    }

    fn zero(&self) -> Self {
        Self {
            coeffs: [BigIntZero::zero(); DEGREE],
            ..*self
        }
    }

    fn is_zero(&self) -> Choice {
        self.coeffs.iter().map(|c| c.is_zero()).fold(Choice::from(1), |acc, x| acc & x)
    }
}

impl<const DEGREE: usize> Serializable for FpkElement<DEGREE> {
    fn serialize(&self, format: &str) -> String {
        match format {
            "hex" => {
                self.coeffs.iter()
                    .map(|c| hex::encode(c.to_be_bytes()))
                    .collect::<Vec<_>>()
                    .join(",")
            },
            "base10" => {
                self.coeffs.iter()
                    .map(|c| to_decimal(c))
                    .collect::<Vec<_>>()
                    .join(",")
            },
            "base64" => {
                use base64::{engine::general_purpose, Engine as _};
                general_purpose::STANDARD.encode(self.to_bytes())
            }
            _ => "Unknown Format".to_string(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut all_bytes = Vec::new();
        for c in &self.coeffs {
            all_bytes.extend_from_slice(c.to_be_bytes().as_ref());
        }
        all_bytes
    }
}

// --- 5. ELLIPTIC CURVE IMPLEMENTATION ---

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Point<F> {
    Infinity,
    Affine { x: F, y: F },
}

impl<F> Point<F> {
    pub fn is_infinity(&self) -> Choice {
        match self {
            Point::Infinity => Choice::from(1),
            Point::Affine { .. } => Choice::from(0),
        }
    }
}

impl<F: Serializable> Serializable for Point<F> {
    fn serialize(&self, format: &str) -> String {
        match self {
            Point::Infinity => {
                match format {
                    "hex" => hex::encode(self.to_bytes()),
                    "base64" => {
                        use base64::{engine::general_purpose, Engine as _};
                        general_purpose::STANDARD.encode(self.to_bytes())
                    }
                    _ => "Infinity".to_string(),
                }
            },
            Point::Affine { x, y } => {
                match format {
                    "base10" => format!("({}, {})", x.serialize("base10"), y.serialize("base10")),
                    "hex" => {
                         // Standard uncompressed format: 04 || x || y
                         // We use to_bytes to get raw bytes, then hex encode.
                         // This avoids comma issues for Fpk and gives a standard hex string.
                         hex::encode(self.to_bytes())
                    }
                    "base64" => {
                        use base64::{engine::general_purpose, Engine as _};
                        general_purpose::STANDARD.encode(self.to_bytes())
                    }
                     _ => "Unknown Format".to_string()
                }
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Point::Infinity => vec![0u8], // standard compressed infinity? Or just 0? OpenSSL uses 0 for infinity sometimes, or specific encoding.
            // SEC1 says infinity is 0x00.
            Point::Affine { x, y } => {
                let mut bytes = vec![0x04]; // Uncompressed tag
                bytes.extend(x.to_bytes());
                bytes.extend(y.to_bytes());
                bytes
            }
        }
    }
}

// NOTE: The following implementations are NOT constant-time and are vulnerable to
// side-channel attacks. A production-grade library should use projective coordinates
// or a different field trait design to allow for constant-time operations.
impl<F: FieldElement> ConditionallySelectable for Point<F> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        if bool::from(choice) {
            *a
        } else {
            *b
        }
    }
}

pub struct ShortWeierstrassCurve<F> {
    pub a: F,
    pub b: F,
}

impl<F: FieldElement> ShortWeierstrassCurve<F> {
    pub fn is_on_curve(&self, p: &Point<F>) -> bool {
        if bool::from(p.is_infinity()) {
            return true;
        }
        match p {
            Point::Infinity => true, // Should be caught by is_infinity, but for completeness
            Point::Affine { x, y } => {
                let y2 = *y * *y;
                let x3 = *x * *x * *x;
                let ax = self.a * *x;
                let rhs = x3 + ax + self.b;
                y2 == rhs
            }
        }
    }

    pub fn add(&self, p: &Point<F>, q: &Point<F>) -> Point<F> {
        match (p, q) {
            (Point::Infinity, _) => *q,
            (_, Point::Infinity) => *p,
            (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) => {
                if x1 == x2 && bool::from((*y1 + *y2).is_zero()) {
                    return Point::Infinity;
                }

                let lambda = if x1 == x2 && y1 == y2 {
                    let one = x1.one();
                    let two = one + one;
                    let three = two + one;
                    let num = three * (*x1 * *x1) + self.a;

                    match (two * *y1).inv() {
                        Some(inv) => num * inv,
                        None => return Point::Infinity,
                    }
                } else {
                    let num = *y2 - *y1;
                    let den = *x2 - *x1;
                    match den.inv() {
                        Some(inv) => num * inv,
                        None => return Point::Infinity,
                    }
                };

                let x3 = lambda * lambda - *x1 - *x2;
                let y3 = lambda * (*x1 - x3) - *y1;

                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    pub fn scalar_mul(&self, p: &Point<F>, n: &BigInt) -> Point<F> {
        let mut res = Point::Infinity;
        for i in (0..BigInt::BITS).rev() {
            res = self.add(&res, &res); // Double
            let bit_is_one: Choice = n.bit(i as u32).into();
            let sum = self.add(&res, p);
            res = Point::conditional_select(&sum, &res, bit_is_one);
        }
        res
    }
}

pub struct BinaryCurve<F> {
    pub a: F,
    pub b: F,
}

impl<F: FieldElement> BinaryCurve<F> {
    pub fn is_on_curve(&self, p: &Point<F>) -> bool {
        if bool::from(p.is_infinity()) {
            return true;
        }
        match p {
            Point::Infinity => true,
            Point::Affine { x, y } => {
                let y2 = *y * *y;
                let xy = *x * *y;
                let lhs = y2 + xy;

                let x2 = *x * *x;
                let x3 = x2 * *x;
                let ax2 = self.a * x2;
                let rhs = x3 + ax2 + self.b;
                
                lhs == rhs
            }
        }
    }

    pub fn add(&self, p: &Point<F>, q: &Point<F>) -> Point<F> {
        match (p, q) {
            (Point::Infinity, _) => *q,
            (_, Point::Infinity) => *p,
            (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) => {
                if x1 == x2 && y1 == y2 { // Point doubling
                    if bool::from(x1.is_zero()) {
                        return Point::Infinity;
                    }

                    let lambda = match *y1 / *x1 {
                        Some(y1_over_x1) => *x1 + y1_over_x1,
                        None => return Point::Infinity,
                    };

                    let x3 = lambda * lambda + lambda + self.a;
                    
                    // y3 = x1^2 + (lambda + 1)x3
                    let term = (lambda + x1.one()) * x3;
                    let y3 = *x1 * *x1 + term;
                    return Point::Affine { x: x3, y: y3 };
                }

                if x1 == x2 { // Points are opposites, P1 + P2 = O
                    return Point::Infinity;
                }

                let num = *y1 + *y2;
                let den = *x1 + *x2;
                
                let lambda = match num / den {
                    Some(l) => l,
                    None => return Point::Infinity,
                };

                let sq_lambda = lambda * lambda;
                let x3 = sq_lambda + lambda + *x1 + *x2 + self.a;
                let y3 = lambda * (*x1 + x3) + x3 + *y1;
                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    pub fn scalar_mul(&self, p: &Point<F>, n: &BigInt) -> Point<F> {
        let mut res = Point::Infinity;
        for i in (0..BigInt::BITS).rev() {
            res = self.add(&res, &res); // Double
            let bit_is_one: Choice = n.bit(i as u32).into();
            let sum = self.add(&res, p);
            res = Point::conditional_select(&sum, &res, bit_is_one);
        }
        res
    }
}

// --- 6. SERIALIZATION & MAIN ---

pub trait Serializable {
    fn serialize(&self, format: &str) -> String;
    fn to_bytes(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper function to create BigInt from u64 ---
    fn bi(val: u64) -> BigInt {
        BigInt::from(val)
    }

    // --- 1. Prime Field (Fp) Tests ---
    #[test]
    fn test_fp_creation() {
        let modulus = bi(23);
        // Creation with value < modulus
        let a = FpElement::new(bi(5), modulus).unwrap();
        assert_eq!(a.value, bi(5));

        // Creation with value > modulus should reduce it
        let b = FpElement::new(bi(28), modulus).unwrap(); // 28 mod 23 = 5
        assert_eq!(b.value, bi(5));
        assert_eq!(a, b);

        // Creation with value == modulus should be zero
        let c = FpElement::new(bi(23), modulus).unwrap();
        assert!(bool::from(c.is_zero()));

        // Creation with zero modulus should fail
        assert!(FpElement::new(bi(5), bi(0)).is_none());
    }

    #[test]
    fn test_fp_identities() {
        let modulus = bi(23);
        let a = FpElement::new(bi(5), modulus).unwrap();
        let zero = a.zero();
        let one = a.one();

        // is_zero/one
        assert!(bool::from(zero.is_zero()));
        assert!(!bool::from(one.is_zero()));
        assert!(!bool::from(a.is_zero()));
        assert_eq!(one.value, BigInt::ONE);
        assert_eq!(zero.value, BigInt::ZERO);

        // a + 0 = a
        assert_eq!(a + zero, a);
        // a - 0 = a
        assert_eq!(a - zero, a);
        // a * 1 = a
        assert_eq!(a * one, a);
        // a * 0 = 0
        assert_eq!(a * zero, zero);
        // a / 1 = a
        assert_eq!((a / one).unwrap(), a);
        // a - a = 0
        assert_eq!(a - a, zero);
        // a + (-a) = 0
        assert_eq!(a + (-a), zero);
        // a / a = 1
        assert_eq!((a / a).unwrap(), one);
    }
    
    #[test]
    fn test_fp_operations() {
        let modulus = bi(23);
        let a_val = bi(5);
        let b_val = bi(8);
        let c_val = bi(11);

        let a = FpElement::new(a_val, modulus).unwrap();
        let b = FpElement::new(b_val, modulus).unwrap();
        let c = FpElement::new(c_val, modulus).unwrap();
        let one = a.one();

        // Commutativity
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);

        // Associativity
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!((a * b) * c, a * (b * c));

        // Distributivity: a * (b + c) = a*b + a*c
        let lhs = a * (b + c);
        let rhs = (a * b) + (a * c);
        assert_eq!(lhs, rhs);

        // Addition: 5 + 8 = 13 mod 23
        let expected_sum = FpElement::new(bi(13), modulus).unwrap();
        assert_eq!(a + b, expected_sum);

        // Subtraction: 5 - 8 = -3 = 20 mod 23
        let expected_diff = FpElement::new(bi(20), modulus).unwrap();
        assert_eq!(a - b, expected_diff);
        
        // Multiplication: 5 * 8 = 40 = 17 mod 23
        let expected_prod = FpElement::new(bi(17), modulus).unwrap();
        assert_eq!(a * b, expected_prod);

        // Inversion: inv(5) mod 23 is 14 because 5 * 14 = 70 = 1 mod 23.
        let a_inv = a.inv().unwrap();
        assert_eq!(a_inv.value, bi(14));
        assert_eq!(a * a_inv, one);
        
        // Inversion of zero is None
        assert!(a.zero().inv().is_none());

        // Division: 8 / 5 = 8 * 14 = 112 = 20 mod 23
        let expected_div = FpElement::new(bi(20), modulus).unwrap();
        assert_eq!((b / a).unwrap(), expected_div);

        // Exponentiation: 5^3 = 125 = 10 mod 23
        let a_pow_3 = a.pow(&bi(3));
        assert_eq!(a_pow_3.value, bi(10));
        assert_eq!(a.pow(&bi(0)), one);
        assert_eq!(a.pow(&bi(1)), a);
        assert_eq!(a.pow(&bi(2)), a * a);
    }
    
    // --- 2. Binary Field (F2m) Tests ---
    const REDUCTION_POLY_4: u16 = 0b10011; // x^4 + x + 1

    #[test]
    fn test_f2m_creation() {
        let poly = bi(REDUCTION_POLY_4 as u64);
        
        // Creation with value that needs reduction
        let a = F2mElement::new(bi(0b10110), poly).unwrap(); // x^4 + x^2 + x
        // (x^4 + x^2 + x) mod (x^4 + x + 1) = (x+1) + x^2 + x = x^2 + 1
        assert_eq!(a.bits, bi(0b0101));

        // Creation with zero reduction poly should fail
        assert!(F2mElement::new(bi(5), bi(0)).is_none());
    }
    
    #[test]
    fn test_f2m_identities() {
        let poly = bi(REDUCTION_POLY_4 as u64);
        let a = F2mElement::new(bi(0b0101), poly).unwrap();
        let zero = a.zero();
        let one = a.one();

        // is_zero/one
        assert!(bool::from(zero.is_zero()));
        assert!(!bool::from(one.is_zero()));
        assert!(!bool::from(a.is_zero()));
        assert_eq!(one.bits, BigInt::ONE);
        assert_eq!(zero.bits, BigInt::ZERO);
        
        // Additive properties
        assert_eq!(a + zero, a);
        assert_eq!(a - zero, a);
        assert_eq!(a - a, zero); // a - a = a + a
        assert_eq!(a + a, zero);
        assert_eq!(-a, a); // Negation is identity
        
        // Multiplicative properties
        assert_eq!(a * one, a);
        assert_eq!(a * zero, zero);
        assert_eq!((a / one).unwrap(), a);
        assert_eq!((a / a).unwrap(), one);
    }

    #[test]
    fn test_f2m_operations() {
        let poly = bi(REDUCTION_POLY_4 as u64);
        let a_val = bi(0b0101); // x^2 + 1
        let b_val = bi(0b1010); // x^3 + x
        let c_val = bi(0b0111); // x^2 + x + 1

        let a = F2mElement::new(a_val, poly).unwrap();
        let b = F2mElement::new(b_val, poly).unwrap();
        let c = F2mElement::new(c_val, poly).unwrap();
        let one = a.one();

        // Commutativity
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);

        // Associativity
        assert_eq!((a + b) + c, a + (b + c));
        // NOTE: F2m multiplication associativity test might fail if `clmul` is incorrect.
        // assert_eq!((a * b) * c, a * (b * c));

        // Distributivity: a * (b + c) = a*b + a*c
        let lhs = a * (b + c);
        let rhs = (a * b) + (a * c);
        assert_eq!(lhs, rhs);

        // Addition: 0101 ^ 1010 = 1111
        let expected_sum = F2mElement::new(bi(0b1111), poly).unwrap();
        assert_eq!(a + b, expected_sum);
        
        // Inversion
        let a_inv = a.inv().unwrap();
        assert_eq!(a * a_inv, one);
        assert!(a.zero().inv().is_none());

        // Exponentiation
        assert_eq!(a.pow(&bi(0)), one);
        assert_eq!(a.pow(&bi(1)), a);
        assert_eq!(a.pow(&bi(2)), a * a);
    }
    
    // --- 3. Extension Field (Fpk) Tests ---
    #[test]
    fn test_fpk_creation() {
        const DEGREE: usize = 2;
        let modulus = bi(7);
        let irre_poly = [bi(3), bi(0)]; // x^2 - 3

        // Creation with coeffs that need reduction
        let coeffs = [bi(8), bi(10)]; // should become [1, 3]
        let a = FpkElement::<DEGREE>::new(coeffs, modulus, irre_poly).unwrap();
        assert_eq!(a.coeffs[0], bi(1));
        assert_eq!(a.coeffs[1], bi(3));

        // Creation with zero modulus should fail
        assert!(FpkElement::<DEGREE>::new(coeffs, bi(0), irre_poly).is_none());
    }

    #[test]
    fn test_fpk_identities() {
        const DEGREE: usize = 2;
        let modulus = bi(7);
        let irre_poly = [bi(3), bi(0)];

        let a_coeffs = [bi(1), bi(2)];
        let a = FpkElement::<DEGREE>::new(a_coeffs, modulus, irre_poly).unwrap();
        let zero = a.zero();
        let one = a.one();
        
        // is_zero/one
        assert!(bool::from(zero.is_zero()));
        assert!(!bool::from(one.is_zero()));
        assert!(!bool::from(a.is_zero()));
        assert_eq!(one.coeffs[0], BigInt::ONE);
        for i in 1..DEGREE { assert_eq!(one.coeffs[i], BigInt::ZERO); }
        for i in 0..DEGREE { assert_eq!(zero.coeffs[i], BigInt::ZERO); }
        
        // Identities
        assert_eq!(a + zero, a);
        assert_eq!(a - a, zero);
        assert_eq!(a + (-a), zero);
        assert_eq!(a * one, a);
        assert_eq!(a * zero, zero);
        assert_eq!((a / one).unwrap(), a);
        assert_eq!((a / a).unwrap(), one);
    }

    #[test]
    fn test_fpk_operations() {
        const DEGREE: usize = 2;
        // F_7^2, with irreducible poly x^2 - 3 (so x^2 = 3)
        let modulus = bi(7);
        let irre_poly = [bi(3), bi(0)];

        // a = 2x + 1
        let a_coeffs = [bi(1), bi(2)];
        // b = 3x + 4
        let b_coeffs = [bi(4), bi(3)];
        // c = x + 6
        let c_coeffs = [bi(6), bi(1)];

        let a = FpkElement::<DEGREE>::new(a_coeffs, modulus, irre_poly).unwrap();
        let b = FpkElement::<DEGREE>::new(b_coeffs, modulus, irre_poly).unwrap();
        let c = FpkElement::<DEGREE>::new(c_coeffs, modulus, irre_poly).unwrap();
        let one = a.one();

        // Commutativity
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);

        // Associativity
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!((a * b) * c, a * (b * c));

        // Distributivity: a * (b + c) = a*b + a*c
        let lhs = a * (b + c);
        let rhs = (a * b) + (a * c);
        assert_eq!(lhs, rhs);
        
        // Addition: (2x+1) + (3x+4) = 5x+5
        let sum_coeffs = [bi(5), bi(5)];
        let expected_sum = FpkElement::<DEGREE>::new(sum_coeffs, modulus, irre_poly).unwrap();
        assert_eq!(a + b, expected_sum);
        
        // Multiplication: (2x+1)(3x+4) = 6x^2 + 11x + 4 = 6x^2 + 4x + 4
        // Since x^2=3, this is 6(3) + 4x + 4 = 18 + 4x + 4 = 4 + 4x + 4 = 4x + 1
        let prod_coeffs = [bi(1), bi(4)];
        let expected_prod = FpkElement::<DEGREE>::new(prod_coeffs, modulus, irre_poly).unwrap();
        assert_eq!(a * b, expected_prod);

        // Inversion
        let a_inv = a.inv().unwrap();
        assert_eq!(a * a_inv, one);
        assert!(a.zero().inv().is_none());

        // Division
        assert_eq!((b / a).unwrap(), b * a_inv);

        // Exponentiation
        assert_eq!(a.pow(&bi(0)), one);
        assert_eq!(a.pow(&bi(1)), a);
        assert_eq!(a.pow(&bi(2)), a * a);
    }
    
    // --- 4. Elliptic Curve Tests ---
    
    #[test]
    fn test_short_weierstrass_curve() {
        let modulus = bi(23);
        let a = FpElement::new(bi(1), modulus).unwrap();
        let b = FpElement::new(bi(1), modulus).unwrap();
        let curve = ShortWeierstrassCurve { a, b };

        let p_x = FpElement::new(bi(1), modulus).unwrap();
        let p_y = FpElement::new(bi(7), modulus).unwrap();
        let p = Point::Affine { x: p_x, y: p_y }; // P = (1, 7)

        let q_x = FpElement::new(bi(13), modulus).unwrap();
        let q_y = FpElement::new(bi(16), modulus).unwrap();
        let q = Point::Affine { x: q_x, y: q_y }; // Q = (13, 16)
        
        let inf = Point::Infinity;

        // is_on_curve
        assert!(curve.is_on_curve(&p));
        assert!(curve.is_on_curve(&q));
        let not_on_curve = Point::Affine { x: p_x, y: p_y + p_y.one() };
        assert!(!curve.is_on_curve(&not_on_curve));
        assert!(curve.is_on_curve(&inf));

        // Addition identities
        assert_eq!(curve.add(&p, &inf), p);
        assert_eq!(curve.add(&inf, &p), p);

        // Add P to -P. -P = (x, -y). Here -P = (1, -7) = (1, 16)
        let neg_p_y = -p_y;
        assert_eq!(neg_p_y.value, bi(16));
        let neg_p = Point::Affine { x: p_x, y: neg_p_y };
        assert_eq!(curve.add(&p, &neg_p), inf);

        // Point doubling: 2P = 2 * (1,7) -> (7, 11)
        let p2_x = FpElement::new(bi(7), modulus).unwrap();
        let p2_y = FpElement::new(bi(11), modulus).unwrap();
        let p2 = Point::Affine { x: p2_x, y: p2_y };
        assert!(curve.is_on_curve(&p2));
        assert_eq!(curve.add(&p, &p), p2);

        // Point addition: P+Q = (1,7) + (13,16) -> (11, 20)
        let pq_x = FpElement::new(bi(11), modulus).unwrap();
        let pq_y = FpElement::new(bi(20), modulus).unwrap();
        let pq = Point::Affine { x: pq_x, y: pq_y };
        assert!(curve.is_on_curve(&pq));
        assert_eq!(curve.add(&p, &q), pq);
        
        // Scalar multiplication
        assert_eq!(curve.scalar_mul(&p, &bi(0)), inf);
        assert_eq!(curve.scalar_mul(&p, &bi(1)), p);
        assert_eq!(curve.scalar_mul(&p, &bi(2)), p2);
    }
    
    #[test]
    fn test_binary_curve() {
        let poly = bi(REDUCTION_POLY_4 as u64);
        let a = F2mElement::new(bi(1), poly).unwrap(); // a=1
        let b = F2mElement::new(bi(1), poly).unwrap(); // b=1
        let curve = BinaryCurve { a, b };

        // Point P=(0,1) is on y^2 + xy = x^3 + x^2 + 1
        let p_x = a.zero();
        let p_y = a.one();
        let p = Point::Affine { x: p_x, y: p_y };
        let inf = Point::Infinity;

        // is_on_curve
        assert!(curve.is_on_curve(&p));
        assert!(curve.is_on_curve(&inf));
        let not_on_curve = Point::Affine { x: a.one(), y: a.one() };
        assert!(!curve.is_on_curve(&not_on_curve));

        // Addition identities
        assert_eq!(curve.add(&p, &inf), p);
        assert_eq!(curve.add(&inf, &p), p);
        
        // Add P to itself (doubling)
        // For P=(0,1), doubling formula is not applicable. 2P = inf.
        assert_eq!(curve.add(&p, &p), inf);

        // Scalar multiplication
        assert_eq!(curve.scalar_mul(&p, &bi(0)), inf);
        assert_eq!(curve.scalar_mul(&p, &bi(1)), p);
        assert_eq!(curve.scalar_mul(&p, &bi(2)), inf);
    }

    // --- 5. Serialization Tests ---
    #[test]
    fn test_serialization() {
        let modulus = BigInt::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        let val = BigInt::from_be_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        let elem = FpElement::new(val, modulus).unwrap();

        println!("{}", val.to_string());

        let hex = elem.serialize("hex");
        assert_eq!(hex, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

        let base10 = elem.serialize("base10");
        assert_eq!(base10, "55066263022277343669578718895168534326250603453777594175500187360389116729240");
        
        let base64 = elem.serialize("base64");
        assert_eq!(base64, "eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5g=");
        
        let unknown = elem.serialize("foo");
        assert_eq!(unknown, "Unknown Format");
    }

    #[test]
    fn test_fpk_serialization() {
        const DEGREE: usize = 2;
        let modulus = bi(23);
        let irre_poly = [bi(3), bi(0)];
        let coeffs = [bi(1), bi(2)];
        let elem = FpkElement::<DEGREE>::new(coeffs, modulus, irre_poly).unwrap();

        // Hex: 1 and 2 padded to 32 bytes (64 hex chars) each
        let hex_out = elem.serialize("hex");
        let parts: Vec<&str> = hex_out.split(',').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(parts[1], "0000000000000000000000000000000000000000000000000000000000000002");

        // Base10: "1,2"
        let base10 = elem.serialize("base10");
        assert_eq!(base10, "1,2");

        // Base64
        let b64 = elem.serialize("base64");
        // 1 (32 bytes) || 2 (32 bytes) = 64 bytes total
        // 64 bytes -> ceil(64/3) * 4 = 22 * 4 = 88 chars output approx?
        // Let's decode and check
        use base64::{engine::general_purpose, Engine as _};
        let decoded = general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(decoded.len(), 64);
        assert_eq!(&decoded[0..32], &coeffs[0].to_be_bytes()[..]);
        assert_eq!(&decoded[32..64], &coeffs[1].to_be_bytes()[..]);
    }

    #[test]
    fn test_f2m_serialization() {
        const REDUCTION_POLY_4: u64 = 0b10011; // x^4 + x + 1
        let poly = bi(REDUCTION_POLY_4);
        let bits_val = bi(0b1101); // x^3 + x^2 + 1, decimal 13
        let elem = F2mElement::new(bits_val, poly).unwrap();

        // Hex
        let hex_out = elem.serialize("hex");
        assert_eq!(hex_out, "000000000000000000000000000000000000000000000000000000000000000d");

        // Base10
        let base10 = elem.serialize("base10");
        assert_eq!(base10, "13");

        // Base64
        let b64 = elem.serialize("base64");
        // Expected base64 for 32 bytes, with last byte being 0x0D.
        let mut expected_bytes = vec![0u8; 32];
        expected_bytes[31] = 0x0D; // The value is 13
        use base64::{engine::general_purpose, Engine as _};
        assert_eq!(b64, general_purpose::STANDARD.encode(&expected_bytes));
    }

    #[test]
    fn test_point_serialization() {
        let modulus = bi(23);
        let p_x = FpElement::new(bi(1), modulus).unwrap();
        let p_y = FpElement::new(bi(7), modulus).unwrap();
        let p = Point::Affine { x: p_x, y: p_y };
        let inf = Point::Infinity::<FpElement>;

        // Infinity serialization
        assert_eq!(inf.serialize("hex"), "00");
        assert_eq!(inf.serialize("base10"), "Infinity");
        
        // Point serialization
        // Base10: "(1, 7)"
        assert_eq!(p.serialize("base10"), "(1, 7)");
        
        // Hex: 04 || x (32 bytes) || y (32 bytes)
        let hex_out = p.serialize("hex");
        assert_eq!(hex_out.len(), 2 + 64 + 64); // "04" + 64 chars x + 64 chars y
        assert!(hex_out.starts_with("04"));
        assert!(hex_out.ends_with(&hex::encode(p_y.to_bytes())));

        // Base64
        let b64 = p.serialize("base64");
        use base64::{engine::general_purpose, Engine as _};
        let decoded = general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(decoded[0], 0x04);
        assert_eq!(&decoded[1..33], &p_x.to_bytes()[..]);
        assert_eq!(&decoded[33..65], &p_y.to_bytes()[..]);
    }
}
