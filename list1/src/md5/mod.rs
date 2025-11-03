mod compression;
pub mod consts;
pub mod generation;

use consts::STATE_INIT;

#[derive(Clone)]
pub enum BlockNumber {
    First, Second,
}

/// 128-bit MD5 digest (16 bytes)
#[derive(Clone)]
pub struct Md5Collider {
    state: [u32; 4],
}

impl Md5Collider {
    /// Create a new hasher and initialize state to MD5 IVs.
    pub fn new() -> Self {
        let mut h = Self { state: [0u32; 4] };
        h.reset();
        h
    }

    /// Reset to the MD5 initial state.
    pub fn reset(&mut self) {
        self.state = STATE_INIT;
    }

    /// Core compression function for one 512-bit (64 byte) block.
    #[inline]
    pub fn compress_block(&mut self, block: &[u8; 64]) {
        compression::compress_block(&mut self.state, block);
    }

    #[inline]
    pub fn verify(&mut self, block: &[u8; 64], block_number: BlockNumber) -> Option<u8> {
        match block_number {
            BlockNumber::First => compression::verify_first_block(&mut self.state, block),
            BlockNumber::Second => compression::verify_second_block(&mut self.state, block),
        }
    }

    /// Finalize and return 16-byte digest (MD5 produces 128-bit digest).
    pub fn finalize(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.state[0].to_le_bytes());
        out[4..8].copy_from_slice(&self.state[1].to_le_bytes());
        out[8..12].copy_from_slice(&self.state[2].to_le_bytes());
        out[12..16].copy_from_slice(&self.state[3].to_le_bytes());
        out
    }

    /// Convenience: return lowercase hex string of the digest
    pub fn finalize_hex(&self) -> String {
        let d = self.finalize();
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn hash_blocks(&mut self, m0: &[u8; 64], m1: &[u8; 64]) -> String {
        self.compress_block(m0);
        self.compress_block(m1);
        self.finalize_hex()
    }

    // TODO: DOES NOT WORK
    pub fn check_collision(&mut self, m0: &[u8; 64], m1: &[u8; 64], m0_prime: &[u8; 64], m1_prime: &[u8; 64]) -> bool {
        let digest = self.hash_blocks(m0, m1);
        let digest_prime = self.hash_blocks(m0_prime, m1_prime);

        digest == digest_prime
    }

    pub fn get_state(&self) -> &[u32; 4] {
        &self.state
    }
}

impl Default for Md5Collider {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------
// Helper: quick example usage (will panic if input not 64-byte aligned)
// -----------------------
//#[cfg(test)]
//mod tests {
    //use super::Md5Collider;

    //#[test]
    //#[should_panic]
    //fn panics_on_non_block() {
        //let mut h = Md5Hasher::new();
        //h.write(b"not-64-bytes");
    //}

    //#[test]
    //fn accepts_single_block() {
        //// Example single 64-byte block (all zeros) — compress_block must be
        //// implemented for this test to pass.
        //let mut h = Md5Hasher::new();
        //h.write(&[0u8; 64]);
        //// After implementing compression you can check finalize_hex()
    //}
//}
