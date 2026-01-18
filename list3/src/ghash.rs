//! GHASH implementation for GCM (Galois/Counter Mode).
//! References: NIST SP 800-38D.
//! 
//! Variant: 
//! - H, AAD blocks, Ciphertext blocks are interpreted as Little Endian integers.
//! - Length block consists of [len(A)_64_BE, len(C)_64_BE] but is interpreted as a Little Endian integer.
//! - Result is Little Endian.

pub fn ghash(h_bytes: &[u8], a: &[u8], c: &[u8]) -> [u8; 16] {
    let h = u128::from_le_bytes(try_into_array(h_bytes));
    
    // Y_0 = 0
    let mut y = 0u128;

    // Process AAD
    for chunk in a.chunks(16) {
        let mut block = [0u8; 16];
        let len = chunk.len();
        block[..len].copy_from_slice(chunk);
        let b = u128::from_le_bytes(block);
        
        y ^= b;
        y = mul_block(y, h);
    }

    // Process Ciphertext
    for chunk in c.chunks(16) {
        let mut block = [0u8; 16];
        let len = chunk.len();
        block[..len].copy_from_slice(chunk);
        let b = u128::from_le_bytes(block);
        
        y ^= b;
        y = mul_block(y, h);
    }

    // Process Lengths: len(A) || len(C)
    // len(A) and len(C) are 64-bit counts of *bits*.
    // Requirement: "padding is big endian" -> The 64-bit counts are BE.
    let len_a_bits = (a.len() as u64) * 8;
    let len_c_bits = (c.len() as u64) * 8;
    
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&len_a_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&len_c_bits.to_be_bytes());
    
    // Requirement: "outher things are little endian" -> Interpret the length block as LE.
    let len_int = u128::from_le_bytes(len_block);
    
    y ^= len_int;
    y = mul_block(y, h);

    y.to_le_bytes()
}

/// Multiplication in GF(2^128) using Standard Polynomial (x^128 + x^7 + x^2 + x + 1).
/// Operates on 128-bit integers representing blocks.
fn mul_block(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = x;
    
    // Standard Reduction Poly: x^128 + x^7 + x^2 + x + 1
    // Represented as 1 + x + x^2 + x^7 = 1 + 2 + 4 + 128 = 135 = 0x87
    // Since we shift left, the x^128 term overflows and we XOR the rest (0x87).
    let r = 0x87;

    // Iterate bits of Y from MSB to LSB (bit 127 down to 0)
    for i in 0..128 {
        // Check bit (127 - i) of Y
        if (y >> (127 - i)) & 1 == 1 {
            z ^= v;
        }

        // Check MSB of V (bit 127)
        let mask = if (v >> 127) & 1 == 1 { r } else { 0 };
        
        // Left shift V
        v <<= 1;
        v ^= mask;
    }
    z
}

fn try_into_array(slice: &[u8]) -> [u8; 16] {
    slice.try_into().expect("Slice must be 16 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghash_zero() {
        let h = [0u8; 16];
        let a = [];
        let c = [];
        let res = ghash(&h, &a, &c);
        assert_eq!(res, [0u8; 16]);
    }

    // NIST Test vectors are for Standard GCM (Big Endian everything).
    // This implementation uses Little Endian for blocks, so these tests would fail.
    /*
    #[test]
    fn test_ghash_nist_vector_4() {
        // NIST GCM Test Vector 4 (derived)
        // Key: feffe9928665731c6d6a8f9467308308
        // H = AES-ECB(Key, 0) -> b83b533708bf535d0aa6e52980d53b78
        let h_hex = "b83b533708bf535d0aa6e52980d53b78";
        let mut h = [0u8; 16];
        hex::decode_to_slice(h_hex, &mut h).unwrap();

        // AAD: feedfacedeadbeeffeedfacedeadbeefabaddad2
        let a_hex = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let a = hex::decode(a_hex).unwrap();

        // Ciphertext: 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985
        let c_hex = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let c = hex::decode(c_hex).unwrap();

        // Expected GHASH = Tag ^ Mask
        // Tag: 5bc94fbc3221a5db94fae95ae7121a47
        // Mask (AES(Key, J0)): 3247184b3c4f69a44dbcd22887bbb418
        // Result: 698e57f70e6ecc7fd9463b7260a9ae5f
        let expected_hex = "698e57f70e6ecc7fd9463b7260a9ae5f";
        
        let res = ghash(&h, &a, &c);
        assert_eq!(hex::encode(res), expected_hex);
    }
    */
}
