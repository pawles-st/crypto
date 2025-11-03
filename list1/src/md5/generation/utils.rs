#[inline(always)]
pub fn op_f_inv(w: u32, x: u32, y: u32, z: u32, s: u32, c: u32, r: u32) -> u32 {
    r.wrapping_sub(x)
        .rotate_right(s)
        .wrapping_sub(c)
        .wrapping_sub(w)
        .wrapping_sub((x & y) | (!x & z))
}

/// Convert an array of little-endian 32-bit words into bytes in big-endian order.
pub fn le_words_to_be_bytes(words: &[u32; 16]) -> [u8; 64] {
    let mut out = Vec::with_capacity(words.len() * 4);
    for &w in words {
    let b = w.to_le_bytes();
        out.extend_from_slice(&[b[0], b[1], b[2], b[3]]);
    }
    out.try_into().unwrap()
}
