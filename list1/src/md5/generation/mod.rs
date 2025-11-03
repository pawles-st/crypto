use rand::prelude::*;
use crate::md5::consts::{RC, FIRST_ROUND_ONE_BITS, FIRST_ROUND_ZERO_BITS, FIRST_ROUND_SAME_BITS};
use crate::md5::BlockNumber;

mod utils;

use utils::*;

/// Generate 16 random `u32` words satisfying given bit constraints.
#[inline(always)]
fn gen_states(
    one_bits: &[u32; 16],
    zero_bits: &[u32; 16],
    same_bits: &[Option<u32>; 16]
) -> [u32; 16] {
    // generate random words
    let mut rng = rand::rng();
    let mut random_states = [0u32; 16];

    for i in 0..16 {
        let ones = one_bits[i];
        let zeros = zero_bits[i];
        let free_mask = !(ones | zeros);
        let mut word = rng.next_u32();

        // pick random bits only where free
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
fn single_message_modification(
    block_number: BlockNumber,
    states: &[u32; 4],
) -> [u8; 64] {
    match block_number {
        BlockNumber::First => {
            unimplemented!("first round smm not implemented");
        },
        BlockNumber::Second => {
            let mut states: Vec<u32> = states.into();
            states.extend(gen_states(&FIRST_ROUND_ONE_BITS, &FIRST_ROUND_ZERO_BITS, &FIRST_ROUND_SAME_BITS));
            let mut data = [0u32; 16];

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
        },
    }
}

/// Generate a message with multi-message modification
fn multi_message_modification() -> [u8; 64] {
    unimplemented!("mmm not implemented");
}

pub fn gen_message(block_number: BlockNumber, state: &[u32; 4]) -> [u8; 64] {
    match block_number {
        BlockNumber::First => {
            unimplemented!("generating messages for first round is not implemented");
        },
        BlockNumber::Second => {
            single_message_modification(BlockNumber::Second, state)
        }
    }
}
