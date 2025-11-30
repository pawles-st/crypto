use rand::prelude::*;
use crate::md5::compression::utils::*;
use crate::md5::compression::verify::verify;
use crate::md5::consts::*;
use crate::md5::BlockNumber;

mod utils;

use utils::*;

pub enum GenType {
    SMM, MMM,
}

/// Generate one random `u32` word satisfying given bit constraints.
#[inline(always)]
fn gen_state(
    one_bits: u32,
    zero_bits: u32,
    same_bits: Option<(u32, u32)>,
    rng: &mut ThreadRng,
) -> u32 {
    let free_mask = !(one_bits | zero_bits);

    // generate random word
    
    let mut word = rng.next_u32();

    // pick random bits only where free, set forced to ones and zeros
    
    let free_values = word & free_mask;
    word = one_bits | free_values;

    // force same bits as previous state where needed
    
    if let Some((mask, same)) = same_bits {
        word = (word & !mask) | (same & mask)
    }

    word
}

/// Generate 16 random `u32` words for first round states, satisfying given bit constraints.
#[inline(always)]
fn gen_first_round_states(
    one_bits: &[u32; 16],
    zero_bits: &[u32; 16],
    same_bits: &[Option<u32>; 16],
    rng: &mut ThreadRng,
) -> [u32; 16] {
    let mut random_states = [0u32; 16];

    for i in 0..16 {
        let ones = one_bits[i];
        let zeros = zero_bits[i];
        let free_mask = !(ones | zeros);

        //generate random word
        
        let mut word = rng.next_u32();

    // pick random bits only where free, set forced to ones and zeros
        
        let free_values = word & free_mask;
        word = ones | free_values;

        // force same bits as previous state where needed
        
        if let Some(mask) = same_bits[i] {
            word = (word & !mask) | (random_states[i - 1] & mask)
        }

        // assemble final word: ones forced high, zeros forced low
        random_states[i] = word;
    }

    random_states
}

/// Generate a message with single-message modification
#[inline(always)]
#[allow(unused_variables)]
fn single_message_modification_first(
    initial_states: [u32; 4],
    rng: &mut ThreadRng,
) -> [u8; 64] {
    [0u8; 64]
}

/// Generate a message with single-message modification
#[inline(always)]
fn single_message_modification_second(
    initial_states: [u32; 4],
    rng: &mut ThreadRng,
) -> [u8; 64] {

    // generate random states and coalesce with initial states

    let mut states: Vec<u32> = initial_states.into();
    states.extend(gen_first_round_states(&FIRST_ROUND_ONE_BITS, &FIRST_ROUND_ZERO_BITS, &FIRST_ROUND_SAME_BITS, rng));
    let mut data = [0u32; 16];

    // compute the message from the states

    data[0] = op_f_inv(states[0], states[1], states[2], states[3], 7, RC[0], states[4]);
    data[1] = op_f_inv(states[3], states[4], states[1], states[2], 12, RC[1], states[5]);
    data[2] = op_f_inv(states[2], states[5], states[4], states[1], 17, RC[2], states[6]);
    data[3] = op_f_inv(states[1], states[6], states[5], states[4], 22, RC[3], states[7]);

    data[4] = op_f_inv(states[4], states[7], states[6], states[5], 7, RC[4], states[8]);
    data[5] = op_f_inv(states[5], states[8], states[7], states[6], 12, RC[5], states[9]);
    data[6] = op_f_inv(states[6], states[9], states[8], states[7], 17, RC[6], states[10]);
    data[7] = op_f_inv(states[7], states[10], states[9], states[8], 22, RC[7], states[11]);

    data[8] = op_f_inv(states[8], states[11], states[10], states[9], 7, RC[8], states[12]);
    data[9] = op_f_inv(states[9], states[12], states[11], states[10], 12, RC[9], states[13]);
    data[10] = op_f_inv(states[10], states[13], states[12], states[11], 17, RC[10], states[14]);
    data[11] = op_f_inv(states[11], states[14], states[13], states[12], 22, RC[11], states[15]);

    data[12] = op_f_inv(states[12], states[15], states[14], states[13], 7, RC[12], states[16]);
    data[13] = op_f_inv(states[13], states[16], states[15], states[14], 12, RC[13], states[17]);
    data[14] = op_f_inv(states[14], states[17], states[16], states[15], 17, RC[14], states[18]);
    data[15] = op_f_inv(states[15], states[18], states[17], states[16], 22, RC[15], states[19]);

    le_words_to_be_bytes(&data)
}

/// Generate a message with multi-message modification
#[inline(always)]
#[allow(unused_variables)]
fn multi_message_modification_first(
    initial_states: [u32; 4],
    rng: &mut ThreadRng,
) -> [u8; 64] {
    [0u8; 64]
}

/// Generate a message with multi-message modification
#[inline(always)]
fn multi_message_modification_second(
    initial_states: [u32; 4],
    rng: &mut ThreadRng,
) -> [u8; 64] {
    let mut conditions_met = false;

    loop { // TODO: do NOT coalesce the states

        // generate random states and coalesce with initial states
        
        let mut states: Vec<u32> = initial_states.into();
        states.extend(gen_first_round_states(&FIRST_ROUND_ONE_BITS, &FIRST_ROUND_ZERO_BITS, &FIRST_ROUND_SAME_BITS, rng));
        let mut data = [0u32; 16];
        
        // compute the message from the states

        data[0] = op_f_inv(states[0], states[1], states[2], states[3], 7, RC[0], states[4]);
        data[1] = op_f_inv(states[3], states[4], states[1], states[2], 12, RC[1], states[5]);
        data[2] = op_f_inv(states[2], states[5], states[4], states[1], 17, RC[2], states[6]);
        data[3] = op_f_inv(states[1], states[6], states[5], states[4], 22, RC[3], states[7]);

        data[4] = op_f_inv(states[4], states[7], states[6], states[5], 7, RC[4], states[8]);
        data[5] = op_f_inv(states[5], states[8], states[7], states[6], 12, RC[5], states[9]);
        data[6] = op_f_inv(states[6], states[9], states[8], states[7], 17, RC[6], states[10]);
        data[7] = op_f_inv(states[7], states[10], states[9], states[8], 22, RC[7], states[11]);

        data[8] = op_f_inv(states[8], states[11], states[10], states[9], 7, RC[8], states[12]);
        data[9] = op_f_inv(states[9], states[12], states[11], states[10], 12, RC[9], states[13]);
        data[10] = op_f_inv(states[10], states[13], states[12], states[11], 17, RC[10], states[14]);
        data[11] = op_f_inv(states[11], states[14], states[13], states[12], 22, RC[11], states[15]);

        data[12] = op_f_inv(states[12], states[15], states[14], states[13], 7, RC[12], states[16]);
        data[13] = op_f_inv(states[13], states[16], states[15], states[14], 12, RC[13], states[17]);
        data[14] = op_f_inv(states[14], states[17], states[16], states[15], 17, RC[14], states[18]);
        data[15] = op_f_inv(states[15], states[18], states[17], states[16], 22, RC[15], states[19]);

        // modify initial two first-round states until conditions
        // for initial four second-round states are met
       
        for _ in 0..4096 {

            // randomise initial two states
            
            states[4] = gen_state(A1_ONE_BITS, A1_ZERO_BITS, None, rng);
            states[5] = gen_state(D1_ONE_BITS, D1_ZERO_BITS, Some((D1_A1_SAME_BITS, states[4])), rng);
            states[5] = (states[5] & !C1_D1_SAME_BITS) | (states[6] & C1_D1_SAME_BITS);
            states[4] = (states[4] & !D1_A1_SAME_BITS) | (states[5] & D1_A1_SAME_BITS);

            // compute the initial two message words for the randomised states
       
            data[0] = op_f_inv(states[0], states[1], states[2], states[3], 7, RC[0], states[4]);
            data[1] = op_f_inv(states[3], states[4], states[1], states[2], 12, RC[1], states[5]);
            data[2] = op_f_inv(states[2], states[5], states[4], states[1], 17, RC[2], states[6]);
            data[3] = op_f_inv(states[1], states[6], states[5], states[4], 22, RC[3], states[7]);
            data[4] = op_f_inv(states[4], states[7], states[6], states[5], 7, RC[4], states[8]);
            data[5] = op_f_inv(states[5], states[8], states[7], states[6], 12, RC[5], states[9]);

            // compute four initial second-round states
            
            let states_20 = op_g(states[16], states[19], states[18], states[17], data[1], RC[16], 5);
            let states_21 = op_g(states[17], states_20, states[19], states[18], data[6], RC[17], 9);
            let states_22 = op_g(states[18], states_21, states_20, states[19], data[11], RC[18], 14);
            let states_23 = op_g(states[19], states_22, states_21, states_20, data[0], RC[19], 20);
            let states_24 = op_g(states_20, states_23, states_22, states_21, data[5], RC[20], 5);

            // check if the second-round states fulfill differential conditions;
            // if not, randomise the initial two states anew
            
            if !verify(states_20, &[states[16], states[19], states[18], states[17]], 0, A5_ZERO_BITS, Some((1, A5_B4_SAME_BITS)), None) { continue; }
            if !verify(states_21, &[states_20, states[19], states[18], states[17]], D5_ONE_BITS, D5_ZERO_BITS, Some((0, D5_A5_SAME_BITS)), None) { continue; }
            if !verify(states_22, &[states_20, states[19], states[18], states_21], 0, C5_ZERO_BITS, None, None) { continue; }
            if !verify(states_23, &[states_20, states[19], states_22, states_21], 0, B5_ZERO_BITS, None, None) { continue; }
            if !verify(states_24, &[states_20, states_23, states_22, states_23], 0, A6_ZERO_BITS, Some((1, A6_B5_SAME_BITS)), None) { continue; }

            conditions_met = true;
            break;
        }

        if conditions_met {

            // compute the other affected words and return

            return le_words_to_be_bytes(&data)
        }
    }
}

/// Generate a candidate for hash collision
#[inline(always)]
pub fn gen_message(state: [u32; 4], block_number: BlockNumber, gen_type: GenType, rng: &mut ThreadRng) -> [u8; 64] {
    match (block_number, gen_type) {
        (BlockNumber::First, GenType::SMM) => {
            unimplemented!("generating messages for first round is not implemented");
        },
        (BlockNumber::First, GenType::MMM) => {
            unimplemented!("generating messages for first round is not implemented");
        },
        (BlockNumber::Second, GenType::SMM) => {
            single_message_modification_second(state, rng)
        },
        (BlockNumber::Second, GenType::MMM) => {
            multi_message_modification_second(state, rng)
        },
    }
}

/// Get a list of possible candidates in MMM by randomising states 7-10
#[inline(always)]
pub fn update_message(initial_states: [u32; 4], input: &[u8; 64], rng: &mut ThreadRng) -> Vec<[u8; 64]> {
    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // compute the states for first round

    let [mut a, mut b, mut c, mut d] = initial_states;
    let mut states = [0u32; 16];

    a = op_f(a, b, c, d, data[0], RC[0], 7);
    d = op_f(d, a, b, c, data[1], RC[1], 12);
    c = op_f(c, d, a, b, data[2], RC[2], 17);
    b = op_f(b, c, d, a, data[3], RC[3], 22);
    states[0] = a;
    states[1] = d;
    states[2] = c;
    states[3] = b;

    a = op_f(a, b, c, d, data[4], RC[4], 7);
    d = op_f(d, a, b, c, data[5], RC[5], 12);
    c = op_f(c, d, a, b, data[6], RC[6], 17);
    b = op_f(b, c, d, a, data[7], RC[7], 22);
    states[4] = a;
    states[5] = d;
    states[6] = c;
    states[7] = b;

    a = op_f(a, b, c, d, data[8], RC[8], 7);
    d = op_f(d, a, b, c, data[9], RC[9], 12);
    c = op_f(c, d, a, b, data[10], RC[10], 17);
    b = op_f(b, c, d, a, data[11], RC[11], 22);
    states[8] = a;
    states[9] = d;
    states[10] = c;
    states[11] = b;

    a = op_f(a, b, c, d, data[12], RC[12], 7);
    d = op_f(d, a, b, c, data[13], RC[13], 12);
    c = op_f(c, d, a, b, data[14], RC[14], 17);
    b = op_f(b, c, d, a, data[15], RC[15], 22);
    states[12] = a;
    states[13] = d;
    states[14] = c;
    states[15] = b;

    // randomise states 7-10 until state 11 fulfills its conditions
    
    loop {
        states[7] = gen_state(B2_ONE_BITS, B2_ZERO_BITS, Some((B2_C2_SAME_BITS, states[6])), rng);
        states[8] = gen_state(A3_ONE_BITS, A3_ZERO_BITS, Some((A3_B2_SAME_BITS, states[7])), rng);
        states[9] = gen_state(D3_ONE_BITS, D3_ZERO_BITS, None, rng);
        states[10] = gen_state(C3_ONE_BITS, C3_ZERO_BITS, Some((C3_D3_SAME_BITS, states[9])), rng);
        states[11] = op_f(states[7], states[10], states[9], states[8], data[11], RC[11], 22);

        if verify(states[11], &[states[8], states[11], states[10], states[9]], B3_ONE_BITS, B3_ZERO_BITS, Some((2, B3_C3_SAME_BITS)), None) { break; }
    }
    
    // adjust words with smm

    data[7] = op_f_inv(states[3], states[6], states[5], states[4], 22, RC[7], states[7]);
    data[8] = op_f_inv(states[4], states[7], states[6], states[5], 7, RC[8], states[8]);
    data[9] = op_f_inv(states[5], states[8], states[7], states[6], 12, RC[9], states[9]);
    data[10] = op_f_inv(states[6], states[9], states[8], states[7], 17, RC[10], states[10]);

    data[12] = op_f_inv(states[8], states[11], states[10], states[9], 7, RC[12], states[12]);
    data[13] = op_f_inv(states[9], states[12], states[11], states[10], 12, RC[13], states[13]);
    data[14] = op_f_inv(states[10], states[13], states[12], states[11], 17, RC[14], states[14]);
    data[15] = op_f_inv(states[11], states[14], states[13], states[12], 22, RC[15], states[15]);

    const I: [u8; 15] = [2, 3, 4, 5, 10, 11, 13, 14, 18, 19, 20, 21, 22, 29, 30];
    const J: [u8; 13] = [2, 3, 4, 5, 10, 11, 20, 21, 22, 27, 28, 29, 30];
    let mut flips = Vec::new();
    for k in 0..32 {
        let bit = (states[10] >> k) & 1;
        if bit == 1 && I.contains(&(k as u8)) {
            flips.push((k, 'I'));
        } else if bit == 0 && J.contains(&(k as u8)) {
            flips.push((k, 'J'));
        }
    }

    let m = flips.len();
    let mut results = Vec::with_capacity(1 << m);

    for mask in 0..(1 << m) {
        let mut xi = states[8];
        let mut xj = states[9];

        for (i, &(k, target)) in flips.iter().enumerate() {
            if (mask >> i) & 1 == 1 {
                match target {
                    'I' => xi ^= 1 << k,
                    'J' => xj ^= 1 << k,
                    _ => unreachable!(),
                }
            }
        }

        results.push((xi, xj));
    }
    
    results.iter().map(|&(xi, xj)| {
        let mut m = data;
        m[8] = op_f_inv(states[4], states[7], states[6], states[5], 7, RC[8], xi);
        m[9] = op_f_inv(states[5], xi, states[7], states[6], 12, RC[9], xj);
        m[10] = op_f_inv(states[6], xj, xi, states[7], 17, RC[10], states[10]);
        m[12] = op_f_inv(xi, states[11], states[10], xj, 7, RC[12], states[12]);
        m[13] = op_f_inv(xj, states[12], states[11], states[10], 12, RC[13], states[13]);
        le_words_to_be_bytes(&m)
    }).collect()
}
