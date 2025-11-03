use crate::consts::*;

#[inline(always)]
fn op_f(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    ((x & y) | (!x & z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}
#[inline(always)]
fn op_g(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    ((x & z) | (y & !z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline(always)]
fn op_h(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    (x ^ y ^ z)
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline(always)]
fn op_i(w: u32, x: u32, y: u32, z: u32, m: u32, c: u32, s: u32) -> u32 {
    (y ^ (x | !z))
        .wrapping_add(w)
        .wrapping_add(m)
        .wrapping_add(c)
        .rotate_left(s)
        .wrapping_add(x)
}

#[inline]
fn compress_block(state: &mut [u32; 4], input: &[u8; 64]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    // round 1
    a = op_f(a, b, c, d, data[0], RC[0], 7);
    if a & A1_ONE_BITS != A1_ONE_BITS || a & A1_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    d = op_f(d, a, b, c, data[1], RC[1], 12);
    if d & D1_ONE_BITS != D1_ONE_BITS || d & D1_ZERO_BITS != 0 || (d & D1_A1_SAME_BITS != a & D1_A1_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    c = op_f(c, d, a, b, data[2], RC[2], 17);
    if c & C1_ONE_BITS != C1_ONE_BITS || c & C1_ZERO_BITS != 0 || (c & C1_D1_SAME_BITS != d & C1_D1_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    b = op_f(b, c, d, a, data[3], RC[3], 22);
    if b & B1_ONE_BITS != B1_ONE_BITS || b & B1_ZERO_BITS != 0 || (b & B1_C1_SAME_BITS != c & B1_C1_SAME_BITS) { *state = [0, 0, 0, 0]; return; }

    a = op_f(a, b, c, d, data[4], RC[4], 7);
    if a & A2_ONE_BITS != A2_ONE_BITS || a & A2_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    d = op_f(d, a, b, c, data[5], RC[5], 12);
    if d & D2_ONE_BITS != D2_ONE_BITS || d & D2_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    c = op_f(c, d, a, b, data[6], RC[6], 17);
    if c & C2_ONE_BITS != C2_ONE_BITS || c & C2_ZERO_BITS != 0 || (c & C2_D2_SAME_BITS != d & C2_D2_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    b = op_f(b, c, d, a, data[7], RC[7], 22);
    if b & B2_ONE_BITS != B2_ONE_BITS || b & B2_ZERO_BITS != 0 || (b & B2_C2_SAME_BITS != c & B2_C2_SAME_BITS) { *state = [0, 0, 0, 0]; return; }

    a = op_f(a, b, c, d, data[8], RC[8], 7);
    if a & A3_ONE_BITS != A3_ONE_BITS || a & A3_ZERO_BITS != 0 || (a & A3_B2_SAME_BITS != b & A3_B2_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    d = op_f(d, a, b, c, data[9], RC[9], 12);
    if d & D3_ONE_BITS != D3_ONE_BITS || d & D3_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    c = op_f(c, d, a, b, data[10], RC[10], 17);
    if c & C3_ONE_BITS != C3_ONE_BITS || c & C3_ZERO_BITS != 0 || (c & C3_D3_SAME_BITS != d & C3_D3_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    b = op_f(b, c, d, a, data[11], RC[11], 22);
    if b & B3_ONE_BITS != B3_ONE_BITS || b & B3_ZERO_BITS != 0 || (b & B3_C3_SAME_BITS != c & B3_C3_SAME_BITS) { *state = [0, 0, 0, 0]; return; }

    a = op_f(a, b, c, d, data[12], RC[12], 7);
    if a & A4_ONE_BITS != A4_ONE_BITS || a & A4_ZERO_BITS != 0 || (a & A3_B2_SAME_BITS != b & A3_B2_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    d = op_f(d, a, b, c, data[13], RC[13], 12);
    if d & D4_ONE_BITS != D4_ONE_BITS || d & D4_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    c = op_f(c, d, a, b, data[14], RC[14], 17);
    if c & C4_ONE_BITS != C4_ONE_BITS || c & C4_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    b = op_f(b, c, d, a, data[15], RC[15], 22);
    if b & B4_ONE_BITS != B4_ONE_BITS || b & B4_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }

    // round 2
    a = op_g(a, b, c, d, data[1], RC[16], 5);
    if a & A5_ZERO_BITS != 0 || (a & A5_B4_SAME_BITS != b & A5_B4_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    d = op_g(d, a, b, c, data[6], RC[17], 9);
    if d & D5_ONE_BITS != D5_ONE_BITS || d & D5_ZERO_BITS != 0 || (d & D5_A5_SAME_BITS != a & D5_A5_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    c = op_g(c, d, a, b, data[11], RC[18], 14);
    if c & C5_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    b = op_g(b, c, d, a, data[0], RC[19], 20);
    if b & B5_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }

    a = op_g(a, b, c, d, data[5], RC[20], 5);
    if a & A6_ZERO_BITS != 0 || (a & A6_B5_SAME_BITS != b & A6_B5_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    d = op_g(d, a, b, c, data[10], RC[21], 9);
    if d & D6_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    c = op_g(c, d, a, b, data[15], RC[22], 14);
    if c & C6_ZERO_BITS != 0 { *state = [0, 0, 0, 0]; return; }
    b = op_g(b, c, d, a, data[4], RC[23], 20);
    if b & B6_C6_DIFFERENT_BITS - c & B6_C6_DIFFERENT_BITS != B6_C6_DIFFERENT_BITS { *state = [0, 0, 0, 0]; return; }

    a = op_g(a, b, c, d, data[9], RC[24], 5);
    d = op_g(d, a, b, c, data[14], RC[25], 9);
    c = op_g(c, d, a, b, data[3], RC[26], 14);
    b = op_g(b, c, d, a, data[8], RC[27], 20);

    a = op_g(a, b, c, d, data[13], RC[28], 5);
    d = op_g(d, a, b, c, data[2], RC[29], 9);
    c = op_g(c, d, a, b, data[7], RC[30], 14);
    b = op_g(b, c, d, a, data[12], RC[31], 20);

    // round 3
    a = op_h(a, b, c, d, data[5], RC[32], 4);
    d = op_h(d, a, b, c, data[8], RC[33], 11);
    c = op_h(c, d, a, b, data[11], RC[34], 16);
    b = op_h(b, c, d, a, data[14], RC[35], 23);

    a = op_h(a, b, c, d, data[1], RC[36], 4);
    d = op_h(d, a, b, c, data[4], RC[37], 11);
    c = op_h(c, d, a, b, data[7], RC[38], 16);
    b = op_h(b, c, d, a, data[10], RC[39], 23);

    a = op_h(a, b, c, d, data[13], RC[40], 4);
    d = op_h(d, a, b, c, data[0], RC[41], 11);
    c = op_h(c, d, a, b, data[3], RC[42], 16);
    b = op_h(b, c, d, a, data[6], RC[43], 23);

    a = op_h(a, b, c, d, data[9], RC[44], 4);
    d = op_h(d, a, b, c, data[12], RC[45], 11);
    c = op_h(c, d, a, b, data[15], RC[46], 16);
    b = op_h(b, c, d, a, data[2], RC[47], 23);
    if b & B12_D12_SAME_BITS != d & B12_D12_SAME_BITS { *state = [0, 0, 0, 0]; return; }

    // round 4
    a = op_i(a, b, c, d, data[0], RC[48], 6);
    if a & A13_C12_SAME_BITS != c & A13_C12_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    d = op_i(d, a, b, c, data[7], RC[49], 10);
    if d & D13_B12_DIFFERENT_BITS - b & D13_B12_DIFFERENT_BITS != D13_B12_DIFFERENT_BITS { *state = [0, 0, 0, 0]; return; }
    c = op_i(c, d, a, b, data[14], RC[50], 15);
    if c & C13_A13_SAME_BITS != a & C13_A13_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    b = op_i(b, c, d, a, data[5], RC[51], 21);
    if b & B13_D13_SAME_BITS != d & B13_D13_SAME_BITS { *state = [0, 0, 0, 0]; return; }

    a = op_i(a, b, c, d, data[12], RC[52], 6);
    if a & A14_C13_SAME_BITS != c & A14_C13_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    d = op_i(d, a, b, c, data[3], RC[53], 10);
    if d & D14_B13_SAME_BITS != b & D14_B13_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    c = op_i(c, d, a, b, data[10], RC[54], 15);
    if c & C14_A14_SAME_BITS != a & C14_A14_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    b = op_i(b, c, d, a, data[1], RC[55], 21);
    if b & B14_D14_SAME_BITS != d & B14_D14_SAME_BITS { *state = [0, 0, 0, 0]; return; }

    a = op_i(a, b, c, d, data[8], RC[56], 6);
    if a & A15_C14_SAME_BITS != c & A15_C14_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    d = op_i(d, a, b, c, data[15], RC[57], 10);
    if d & D15_B14_SAME_BITS != b & D15_B14_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    c = op_i(c, d, a, b, data[6], RC[58], 15);
    if c & C15_A15_SAME_BITS != a & C15_A15_SAME_BITS { *state = [0, 0, 0, 0]; return; }
    b = op_i(b, c, d, a, data[13], RC[59], 21);
    if b & B15_D15_DIFFERENT_BITS - d & B15_D15_DIFFERENT_BITS != B15_D15_DIFFERENT_BITS { *state = [0, 0, 0, 0]; return; }

    a = op_i(a, b, c, d, data[4], RC[60], 6);
    if a & A16_ONE_BITS != A16_ONE_BITS || (a & A16_C15_SAME_BITS != c & A16_C15_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    d = op_i(d, a, b, c, data[11], RC[61], 10);
    if d & D16_ONE_BITS != D16_ONE_BITS || (d & D16_B15_SAME_BITS != b & D16_B15_SAME_BITS) { *state = [0, 0, 0, 0]; return; }
    c = op_i(c, d, a, b, data[2], RC[62], 15);
    b = op_i(b, c, d, a, data[9], RC[63], 21);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[inline]
pub(super) fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block)
    }
}
