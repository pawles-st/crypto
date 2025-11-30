mod compression;
pub mod consts;
pub mod generation;

use consts::STATE_INIT;

pub use generation::GenType;

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
    pub fn verify(&mut self, block: &[u8; 64], block_number: BlockNumber, gen_type: GenType) -> Option<u8> {
        match (block_number, gen_type) {
            (BlockNumber::First, GenType::SMM) => compression::smm_verify_first_block(&mut self.state, block),
            (BlockNumber::First, GenType::MMM) => compression::mmm_verify_first_block(&mut self.state, block),
            (BlockNumber::Second, GenType::SMM) => compression::smm_verify_second_block(&mut self.state, block),
            (BlockNumber::Second, GenType::MMM) => compression::mmm_verify_second_block(&mut self.state, block),
        }
    }

    #[inline]
    pub fn verify_full(&mut self, block: &[u8; 64], block_number: BlockNumber) -> Option<u8> {
        match block_number {
            BlockNumber::First => compression::full_verify_first_block(&mut self.state, block),
            BlockNumber::Second => compression::full_verify_second_block(&mut self.state, block),
        }
    }

    /// Finalize and return 16-byte digest (128-bit).
    pub fn finalize(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.state[0].to_le_bytes());
        out[4..8].copy_from_slice(&self.state[1].to_le_bytes());
        out[8..12].copy_from_slice(&self.state[2].to_le_bytes());
        out[12..16].copy_from_slice(&self.state[3].to_le_bytes());
        out
    }

    /// Convenience: finalize and return lowercase hex string of the 128-bit digest
    pub fn finalize_hex(&self) -> String {
        let digest = self.finalize();
        hex::encode(digest)
    }

    /// Return the digest of a two-block message (m0, m1)
    pub fn hash_blocks(&mut self, m0: &[u8; 64], m1: &[u8; 64]) -> [u8; 16] {
        self.compress_block(m0);
        self.compress_block(m1);
        self.finalize()
    }
    
    /// Convenience: return hex digest of a two-block message (m0, m1)
    pub fn hash_blocks_hex(&mut self, m0: &[u8; 64], m1: &[u8; 64]) -> String {
        self.compress_block(m0);
        self.compress_block(m1);
        self.finalize_hex()
    }

    pub fn get_state(&self) -> [u32; 4] {
        self.state
    }
}

impl Default for Md5Collider {
    fn default() -> Self {
        Self::new()
    }
}
