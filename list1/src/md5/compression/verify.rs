use crate::md5::consts::*;
use super::utils::*;

#[inline(always)]
pub fn verify(
    value: u32,
    state: &[u32; 4],
    one_bits: u32,
    zero_bits: u32,
    same_bits: Option<(usize, u32)>,
    different_bits: Option<(usize, u32)>)
-> bool {
    // All required-one bits must be set
    if (value & one_bits) != one_bits {
        return false;
    }

    // All required-zero bits must be clear
    if (value & zero_bits) != 0 {
        return false;
    }

    // Optional: certain bits must be equal to the same bits from another state word
    if let Some((idx, mask)) = same_bits {
        if idx >= state.len() {
            return false;
        }
        if (value & mask) != (state[idx] & mask) {
            return false;
        }
    }

    // Optional: certain bits must be different from the same bits from another state word
    if let Some((idx, mask)) = different_bits {
        if idx >= state.len() {
            return false;
        }
        if ((value ^ state[idx]) & mask) != mask {
            return false;
        }
    }

    true
}

#[inline]
#[allow(unused_variables)]
pub fn full_verify_first_block(state: &mut [u32; 4], input: &[u8; 64]) -> Option<u8> {
    unimplemented!("First block check is not implemented");
}

#[inline]
#[allow(unused_variables)]
pub fn smm_verify_first_block(state: &mut [u32; 4], input: &[u8; 64]) -> Option<u8> {
    unimplemented!("First block check is not implemented");
}

#[inline]
#[allow(unused_variables)]
pub fn mmm_verify_first_block(state: &mut [u32; 4], input: &[u8; 64]) -> Option<u8> {
    unimplemented!("First block check is not implemented");
}

#[inline]
pub fn smm_verify_second_block(state: &mut [u32; 4], input: &[u8; 64]) -> Option<u8> {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // round 1
    a = op_f(a, b, c, d, data[0], RC[0], 7);
    d = op_f(d, a, b, c, data[1], RC[1], 12);
    c = op_f(c, d, a, b, data[2], RC[2], 17);
    b = op_f(b, c, d, a, data[3], RC[3], 22);


    a = op_f(a, b, c, d, data[4], RC[4], 7);
    d = op_f(d, a, b, c, data[5], RC[5], 12);
    c = op_f(c, d, a, b, data[6], RC[6], 17);
    b = op_f(b, c, d, a, data[7], RC[7], 22);


    a = op_f(a, b, c, d, data[8], RC[8], 7);
    d = op_f(d, a, b, c, data[9], RC[9], 12);
    c = op_f(c, d, a, b, data[10], RC[10], 17);
    b = op_f(b, c, d, a, data[11], RC[11], 22);


    a = op_f(a, b, c, d, data[12], RC[12], 7);
    d = op_f(d, a, b, c, data[13], RC[13], 12);
    c = op_f(c, d, a, b, data[14], RC[14], 17);
    b = op_f(b, c, d, a, data[15], RC[15], 22);


    // round 2
    a = op_g(a, b, c, d, data[1], RC[16], 5);
    d = op_g(d, a, b, c, data[6], RC[17], 9);
    if !verify(d, &[a, b, c, d], D5_ONE_BITS, D5_ZERO_BITS, Some((0, D5_A5_SAME_BITS)), None) { return Some(17); }

    c = op_g(c, d, a, b, data[11], RC[18], 14);
    if !verify(c, &[a, b, c, d], 0, C5_ZERO_BITS, None, None) { return Some(18); }

    b = op_g(b, c, d, a, data[0], RC[19], 20);
    if !verify(b, &[a, b, c, d], 0, B5_ZERO_BITS, None, None) { return Some(19); }


    a = op_g(a, b, c, d, data[5], RC[20], 5);
    if !verify(a, &[a, b, c, d], 0, A6_ZERO_BITS, Some((1, A6_B5_SAME_BITS)), None) { return Some(20); }

    d = op_g(d, a, b, c, data[10], RC[21], 9);
    if !verify(d, &[a, b, c, d], 0, D6_ZERO_BITS, None, None) { return Some(21); }

    c = op_g(c, d, a, b, data[15], RC[22], 14);
    if !verify(c, &[a, b, c, d], 0, C6_ZERO_BITS, None, None) { return Some(22); }

    b = op_g(b, c, d, a, data[4], RC[23], 20);
    if !verify(b, &[a, b, c, d], 0, 0, None, Some((2, B6_C6_DIFFERENT_BITS))) { return Some(23); }


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
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B12_D12_SAME_BITS)), None) { return Some(47); }


    // round 4
    a = op_i(a, b, c, d, data[0], RC[48], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A13_C12_SAME_BITS)), None) { return Some(48); }

    d = op_i(d, a, b, c, data[7], RC[49], 10);
    if !verify(d, &[a, b, c, d], 0, 0, None, Some((1, D13_B12_DIFFERENT_BITS))) { return Some(49); }

    c = op_i(c, d, a, b, data[14], RC[50], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C13_A13_SAME_BITS)), None) { return Some(50); }

    b = op_i(b, c, d, a, data[5], RC[51], 21);
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B13_D13_SAME_BITS)), None) { return Some(51); }


    a = op_i(a, b, c, d, data[12], RC[52], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A14_C13_SAME_BITS)), None) { return Some(52); }

    d = op_i(d, a, b, c, data[3], RC[53], 10);
    if !verify(d, &[a, b, c, d], 0, 0, Some((1, D14_B13_SAME_BITS)), None) { return Some(53); }

    c = op_i(c, d, a, b, data[10], RC[54], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C14_A14_SAME_BITS)), None) { return Some(54); }

    b = op_i(b, c, d, a, data[1], RC[55], 21);
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B14_D14_SAME_BITS)), None) { return Some(55); }


    a = op_i(a, b, c, d, data[8], RC[56], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A15_C14_SAME_BITS)), None) { return Some(56); }

    d = op_i(d, a, b, c, data[15], RC[57], 10);
    if !verify(d, &[a, b, c, d], 0, 0, Some((1, D15_B14_SAME_BITS)), None) { return Some(57); }

    c = op_i(c, d, a, b, data[6], RC[58], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C15_A15_SAME_BITS)), None) { return Some(58); }

    b = op_i(b, c, d, a, data[13], RC[59], 21);
    if !verify(b, &[a, b, c, d], 0, 0, None, Some((3, B15_D15_DIFFERENT_BITS))) { return Some(59); }


    a = op_i(a, b, c, d, data[4], RC[60], 6);
    if !verify(a, &[a, b, c, d], A16_ONE_BITS, 0, Some((2, A16_C15_SAME_BITS)), None) { return Some(60); }

    d = op_i(d, a, b, c, data[11], RC[61], 10);
    if !verify(d, &[a, b, c, d], D16_ONE_BITS, 0, Some((1, D16_B15_SAME_BITS)), None) { return Some(61); }

    c = op_i(c, d, a, b, data[2], RC[62], 15);
    b = op_i(b, c, d, a, data[9], RC[63], 21);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);

    None
}

#[inline]
pub fn mmm_verify_second_block(state: &mut [u32; 4], input: &[u8; 64]) -> Option<u8> {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // round 1
    a = op_f(a, b, c, d, data[0], RC[0], 7);
    d = op_f(d, a, b, c, data[1], RC[1], 12);
    c = op_f(c, d, a, b, data[2], RC[2], 17);
    b = op_f(b, c, d, a, data[3], RC[3], 22);


    a = op_f(a, b, c, d, data[4], RC[4], 7);
    d = op_f(d, a, b, c, data[5], RC[5], 12);
    c = op_f(c, d, a, b, data[6], RC[6], 17);
    b = op_f(b, c, d, a, data[7], RC[7], 22);


    a = op_f(a, b, c, d, data[8], RC[8], 7);
    d = op_f(d, a, b, c, data[9], RC[9], 12);
    c = op_f(c, d, a, b, data[10], RC[10], 17);
    b = op_f(b, c, d, a, data[11], RC[11], 22);


    a = op_f(a, b, c, d, data[12], RC[12], 7);
    d = op_f(d, a, b, c, data[13], RC[13], 12);
    c = op_f(c, d, a, b, data[14], RC[14], 17);
    b = op_f(b, c, d, a, data[15], RC[15], 22);


    // round 2
    a = op_g(a, b, c, d, data[1], RC[16], 5);
    d = op_g(d, a, b, c, data[6], RC[17], 9);
    c = op_g(c, d, a, b, data[11], RC[18], 14);
    b = op_g(b, c, d, a, data[0], RC[19], 20);


    a = op_g(a, b, c, d, data[5], RC[20], 5);
    if !verify(a, &[a, b, c, d], 0, A6_ZERO_BITS, Some((1, A6_B5_SAME_BITS)), None) { return Some(20); }

    d = op_g(d, a, b, c, data[10], RC[21], 9);
    if !verify(d, &[a, b, c, d], 0, D6_ZERO_BITS, None, None) { return Some(21); }

    c = op_g(c, d, a, b, data[15], RC[22], 14);
    if !verify(c, &[a, b, c, d], 0, C6_ZERO_BITS, None, None) { return Some(22); }

    b = op_g(b, c, d, a, data[4], RC[23], 20);
    if !verify(b, &[a, b, c, d], 0, 0, None, Some((2, B6_C6_DIFFERENT_BITS))) { return Some(23); }


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
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B12_D12_SAME_BITS)), None) { return Some(47); }


    // round 4
    a = op_i(a, b, c, d, data[0], RC[48], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A13_C12_SAME_BITS)), None) { return Some(48); }

    d = op_i(d, a, b, c, data[7], RC[49], 10);
    if !verify(d, &[a, b, c, d], 0, 0, None, Some((1, D13_B12_DIFFERENT_BITS))) { return Some(49); }

    c = op_i(c, d, a, b, data[14], RC[50], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C13_A13_SAME_BITS)), None) { return Some(50); }

    b = op_i(b, c, d, a, data[5], RC[51], 21);
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B13_D13_SAME_BITS)), None) { return Some(51); }


    a = op_i(a, b, c, d, data[12], RC[52], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A14_C13_SAME_BITS)), None) { return Some(52); }

    d = op_i(d, a, b, c, data[3], RC[53], 10);
    if !verify(d, &[a, b, c, d], 0, 0, Some((1, D14_B13_SAME_BITS)), None) { return Some(53); }

    c = op_i(c, d, a, b, data[10], RC[54], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C14_A14_SAME_BITS)), None) { return Some(54); }

    b = op_i(b, c, d, a, data[1], RC[55], 21);
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B14_D14_SAME_BITS)), None) { return Some(55); }


    a = op_i(a, b, c, d, data[8], RC[56], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A15_C14_SAME_BITS)), None) { return Some(56); }

    d = op_i(d, a, b, c, data[15], RC[57], 10);
    if !verify(d, &[a, b, c, d], 0, 0, Some((1, D15_B14_SAME_BITS)), None) { return Some(57); }

    c = op_i(c, d, a, b, data[6], RC[58], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C15_A15_SAME_BITS)), None) { return Some(58); }

    b = op_i(b, c, d, a, data[13], RC[59], 21);
    if !verify(b, &[a, b, c, d], 0, 0, None, Some((3, B15_D15_DIFFERENT_BITS))) { return Some(59); }


    a = op_i(a, b, c, d, data[4], RC[60], 6);
    if !verify(a, &[a, b, c, d], A16_ONE_BITS, 0, Some((2, A16_C15_SAME_BITS)), None) { return Some(60); }

    d = op_i(d, a, b, c, data[11], RC[61], 10);
    if !verify(d, &[a, b, c, d], D16_ONE_BITS, 0, Some((1, D16_B15_SAME_BITS)), None) { return Some(61); }

    c = op_i(c, d, a, b, data[2], RC[62], 15);
    b = op_i(b, c, d, a, data[9], RC[63], 21);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);

    None
}

#[inline]
pub fn full_verify_second_block(state: &mut [u32; 4], input: &[u8; 64]) -> Option<u8> {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // round 1
    a = op_f(a, b, c, d, data[0], RC[0], 7);
    if !verify(a, &[a, b, c, d], A1_ONE_BITS, A1_ZERO_BITS, None, None) { return Some(0); }

    d = op_f(d, a, b, c, data[1], RC[1], 12);
    if !verify(d, &[a, b, c, d], D1_ONE_BITS, D1_ZERO_BITS, Some((0, D1_A1_SAME_BITS)), None) { return Some(1); }

    c = op_f(c, d, a, b, data[2], RC[2], 17);
    if !verify(c, &[a, b, c, d], C1_ONE_BITS, C1_ZERO_BITS, Some((3, C1_D1_SAME_BITS)), None) { return Some(2); }

    b = op_f(b, c, d, a, data[3], RC[3], 22);
    if !verify(b, &[a, b, c, d], B1_ONE_BITS, B1_ZERO_BITS, Some((2, B1_C1_SAME_BITS)), None) { return Some(3); }


    a = op_f(a, b, c, d, data[4], RC[4], 7);
    if !verify(a, &[a, b, c, d], A2_ONE_BITS, A2_ZERO_BITS, None, None) { return Some(4); }

    d = op_f(d, a, b, c, data[5], RC[5], 12);
    if !verify(d, &[a, b, c, d], D2_ONE_BITS, D2_ZERO_BITS, None, None) { return Some(5); }

    c = op_f(c, d, a, b, data[6], RC[6], 17);
    if !verify(c, &[a, b, c, d], C2_ONE_BITS, C2_ZERO_BITS, Some((3, C2_D2_SAME_BITS)), None) { return Some(6); }

    b = op_f(b, c, d, a, data[7], RC[7], 22);
    if !verify(b, &[a, b, c, d], B2_ONE_BITS, B2_ZERO_BITS, Some((2, B2_C2_SAME_BITS)), None) { return Some(7); }


    a = op_f(a, b, c, d, data[8], RC[8], 7);
    if !verify(a, &[a, b, c, d], A3_ONE_BITS, A3_ZERO_BITS, Some((1, A3_B2_SAME_BITS)), None) { return Some(8); }

    d = op_f(d, a, b, c, data[9], RC[9], 12);
    if !verify(d, &[a, b, c, d], D3_ONE_BITS, D3_ZERO_BITS, None, None) { return Some(9); }

    c = op_f(c, d, a, b, data[10], RC[10], 17);
    if !verify(c, &[a, b, c, d], C3_ONE_BITS, C3_ZERO_BITS, Some((3, C3_D3_SAME_BITS)), None) { return Some(10); }

    b = op_f(b, c, d, a, data[11], RC[11], 22);
    if !verify(b, &[a, b, c, d], B3_ONE_BITS, B3_ZERO_BITS, Some((2, B3_C3_SAME_BITS)), None) { return Some(11); }


    a = op_f(a, b, c, d, data[12], RC[12], 7);
    if !verify(a, &[a, b, c, d], A4_ONE_BITS, A4_ZERO_BITS, None, None) { return Some(12); }

    d = op_f(d, a, b, c, data[13], RC[13], 12);
    if !verify(d, &[a, b, c, d], D4_ONE_BITS, D4_ZERO_BITS, None, None) { return Some(13); }

    c = op_f(c, d, a, b, data[14], RC[14], 17);
    if !verify(c, &[a, b, c, d], C4_ONE_BITS, C4_ZERO_BITS, None, None) { return Some(14); }

    b = op_f(b, c, d, a, data[15], RC[15], 22);
    if !verify(b, &[a, b, c, d], B4_ONE_BITS, B4_ZERO_BITS, None, None) { return Some(15); }


    // round 2
    a = op_g(a, b, c, d, data[1], RC[16], 5);
    if !verify(a, &[a, b, c, d], 0, A5_ZERO_BITS, Some((1, A5_B4_SAME_BITS)), None) { return Some(16); }

    d = op_g(d, a, b, c, data[6], RC[17], 9);
    if !verify(d, &[a, b, c, d], D5_ONE_BITS, D5_ZERO_BITS, Some((0, D5_A5_SAME_BITS)), None) { return Some(17); }

    c = op_g(c, d, a, b, data[11], RC[18], 14);
    if !verify(c, &[a, b, c, d], 0, C5_ZERO_BITS, None, None) { return Some(18); }

    b = op_g(b, c, d, a, data[0], RC[19], 20);
    if !verify(b, &[a, b, c, d], 0, B5_ZERO_BITS, None, None) { return Some(19); }


    a = op_g(a, b, c, d, data[5], RC[20], 5);
    if !verify(a, &[a, b, c, d], 0, A6_ZERO_BITS, Some((1, A6_B5_SAME_BITS)), None) { return Some(20); }

    d = op_g(d, a, b, c, data[10], RC[21], 9);
    if !verify(d, &[a, b, c, d], 0, D6_ZERO_BITS, None, None) { return Some(21); }

    c = op_g(c, d, a, b, data[15], RC[22], 14);
    if !verify(c, &[a, b, c, d], 0, C6_ZERO_BITS, None, None) { return Some(22); }

    b = op_g(b, c, d, a, data[4], RC[23], 20);
    if !verify(b, &[a, b, c, d], 0, 0, None, Some((2, B6_C6_DIFFERENT_BITS))) { return Some(23); }


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
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B12_D12_SAME_BITS)), None) { return Some(47); }


    // round 4
    a = op_i(a, b, c, d, data[0], RC[48], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A13_C12_SAME_BITS)), None) { return Some(48); }

    d = op_i(d, a, b, c, data[7], RC[49], 10);
    if !verify(d, &[a, b, c, d], 0, 0, None, Some((1, D13_B12_DIFFERENT_BITS))) { return Some(49); }

    c = op_i(c, d, a, b, data[14], RC[50], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C13_A13_SAME_BITS)), None) { return Some(50); }

    b = op_i(b, c, d, a, data[5], RC[51], 21);
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B13_D13_SAME_BITS)), None) { return Some(51); }


    a = op_i(a, b, c, d, data[12], RC[52], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A14_C13_SAME_BITS)), None) { return Some(52); }

    d = op_i(d, a, b, c, data[3], RC[53], 10);
    if !verify(d, &[a, b, c, d], 0, 0, Some((1, D14_B13_SAME_BITS)), None) { return Some(53); }

    c = op_i(c, d, a, b, data[10], RC[54], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C14_A14_SAME_BITS)), None) { return Some(54); }

    b = op_i(b, c, d, a, data[1], RC[55], 21);
    if !verify(b, &[a, b, c, d], 0, 0, Some((3, B14_D14_SAME_BITS)), None) { return Some(55); }


    a = op_i(a, b, c, d, data[8], RC[56], 6);
    if !verify(a, &[a, b, c, d], 0, 0, Some((2, A15_C14_SAME_BITS)), None) { return Some(56); }

    d = op_i(d, a, b, c, data[15], RC[57], 10);
    if !verify(d, &[a, b, c, d], 0, 0, Some((1, D15_B14_SAME_BITS)), None) { return Some(57); }

    c = op_i(c, d, a, b, data[6], RC[58], 15);
    if !verify(c, &[a, b, c, d], 0, 0, Some((0, C15_A15_SAME_BITS)), None) { return Some(58); }

    b = op_i(b, c, d, a, data[13], RC[59], 21);
    if !verify(b, &[a, b, c, d], 0, 0, None, Some((3, B15_D15_DIFFERENT_BITS))) { return Some(59); }


    a = op_i(a, b, c, d, data[4], RC[60], 6);
    if !verify(a, &[a, b, c, d], A16_ONE_BITS, 0, Some((2, A16_C15_SAME_BITS)), None) { return Some(60); }

    d = op_i(d, a, b, c, data[11], RC[61], 10);
    if !verify(d, &[a, b, c, d], D16_ONE_BITS, 0, Some((1, D16_B15_SAME_BITS)), None) { return Some(61); }

    c = op_i(c, d, a, b, data[2], RC[62], 15);
    b = op_i(b, c, d, a, data[9], RC[63], 21);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);

    None
}
