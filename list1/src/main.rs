mod md5;

use md5::{BlockNumber, Md5Collider};
use md5::generation::{gen_message, update_message, GenType};

// first testing m0

const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";

// second testing m0
        
//const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";

// decode a single hex block (512 bits) into bytes
#[inline(always)]
fn decode_hex_block(hex_str: &str) -> [u8; 64] {
    let mut buf = [0u8; 64];
    hex::decode_to_slice(hex_str, &mut buf).expect("Hex decoding failed");
    buf
}

// modify a le word in a bytes array 
#[inline(always)]
pub fn modify_word_le(msg: &mut [u8], k: usize, delta: u32, add: bool) {
    // extract word
    let offset = k * 4;
    let mut word_bytes = [0u8; 4];
    word_bytes.copy_from_slice(&msg[offset..offset + 4]);
    let mut word = u32::from_le_bytes(word_bytes);

    // modify
    if add {
        word = word.wrapping_add(delta);
    } else {
        word = word.wrapping_sub(delta);
    }

    // write back
    msg[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
}
    
fn check_collision(m0: &[u8; 64], m1: &[u8; 64], m0_prime: &[u8; 64], m1_prime: &[u8; 64]) -> bool {
    let mut hasher = Md5Collider::new();
    let digest = hasher.hash_blocks(m0, m1);
    hasher.reset();
    let digest_prime = hasher.hash_blocks(m0_prime, m1_prime);

    digest == digest_prime
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let m0 = decode_hex_block(M0_HEX);
    //let m1 = decode_hex_block(M1_HEX);
    //let m0_prime_test = decode_hex_block(M0_PRIME_HEX);
    //let m1_prime_test = decode_hex_block(M1_PRIME_HEX);

    let mut block: BlockNumber;
    let mut rng = rand::rng();

    // first round (TODO)

    block = BlockNumber::First;

    let mut hasher = Md5Collider::new();
    hasher.compress_block(&m0);

    let mut m0_prime = m0.clone();
    modify_word_le(&mut m0_prime, 4, 1 << 31, true);
    modify_word_le(&mut m0_prime, 11, 1 << 15, true);
    modify_word_le(&mut m0_prime, 14, 1 << 31, true);

    // second round

    block = BlockNumber::Second;
    let state = hasher.get_state();

    let mut i: usize = 0;
    let mut next_stage = 1;
    
    let mut j = 0;
    let mut collision_found = false;
    while !collision_found {
        let mut candidates = vec![gen_message(state, block.clone(), GenType::MMM, &mut rng)];

        // search collision candidates

        for _ in 0..4096 {
            let last_candidate = candidates[0];

            for m1 in candidates {
                let mut round_hasher = hasher.clone();
                let result = round_hasher.verify_full(&m1, block.clone());

                if result.is_none() { // m1 satisfies differentials
                    j += 1;
                    let mut m1_prime = m1.clone();
                    modify_word_le(&mut m1_prime, 4, 1 << 31, true);
                    modify_word_le(&mut m1_prime, 11, 1 << 15, false);
                    modify_word_le(&mut m1_prime, 14, 1 << 31, true);
                   
                    // check collision

                    let digest = round_hasher.finalize();
                    let digest_prime = Md5Collider::new().hash_blocks(&m0_prime, &m1_prime);
                    
                    if digest == digest_prime {
                        collision_found = true;
                        
                        let m0_hex = hex::encode(m0);
                        let m1_hex = hex::encode(m1);
                        println!("collision found!\nm0 = {}\nm1 = {}", m0_hex, m1_hex);
                        println!("total final candidates: {}", j);
                        break;
                    }
                }
                
                i += 1;
                if i == next_stage {
                    next_stage <<= 1;
                    println!("computed hashes: {i}");
                }
            }

            if collision_found { break; }

            candidates = update_message(state, &last_candidate, &mut rng);
            //println!("new candidates: {}", candidates.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_equality_1() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
        const M1_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db19b0ad835cca7e3";
        const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
        const M1_PRIME_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739a47f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db19b0a5835cca7e3";
        const H_HEX: &str = "1f160396bf9d0fa3bcff659fefc71ff4";

        let m0 = decode_hex_block(M0_HEX);
        let m1 = decode_hex_block(M1_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks_hex(&m0, &m1), H_HEX);
        
        let m0_prime = decode_hex_block(M0_PRIME_HEX);
        let m1_prime = decode_hex_block(M1_PRIME_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks_hex(&m0_prime, &m1_prime), H_HEX);
    }

    #[test]
    fn test_hash_equality_2() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
        const M1_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";
        const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
        const M1_PRIME_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";
        const H_HEX: &str = "19705e8d084e8061586b5d7115c02463";

        let m0 = decode_hex_block(M0_HEX);
        let m1 = decode_hex_block(M1_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks_hex(&m0, &m1), H_HEX);
        
        let m0_prime = decode_hex_block(M0_PRIME_HEX);
        let m1_prime = decode_hex_block(M1_PRIME_HEX);
        let mut hasher = Md5Collider::new();
        assert_eq!(hasher.hash_blocks_hex(&m0_prime, &m1_prime), H_HEX);
    }

    #[test]
    fn test_collision_1() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
        const M1_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db19b0ad835cca7e3";
        const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
        const M1_PRIME_HEX : &str = "960b1dd1dc417b9ce4d897f45a6555d535739a47f0ebfd0c3029f166d109b18f75277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db19b0a5835cca7e3";

        let m0 = decode_hex_block(M0_HEX);
        let m0_prime_test = decode_hex_block(M0_PRIME_HEX);
        let mut m0_prime = m0.clone();

        modify_word_le(&mut m0_prime, 4, 1 << 31, true);
        modify_word_le(&mut m0_prime, 11, 1 << 15, true);
        modify_word_le(&mut m0_prime, 14, 1 << 31, true);
        assert_eq!(m0_prime, m0_prime_test);
        
        let m1 = decode_hex_block(M1_HEX);
        let m1_prime_test = decode_hex_block(M1_PRIME_HEX);
        let mut m1_prime = m1.clone();

        modify_word_le(&mut m1_prime, 4, 1 << 31, true);
        modify_word_le(&mut m1_prime, 11, 1 << 15, false);
        modify_word_le(&mut m1_prime, 14, 1 << 31, true);
        assert_eq!(m1_prime, m1_prime_test);

        let mut hasher = Md5Collider::new();
        hasher.compress_block(&m0);
        let result = hasher.verify_full(&m1, BlockNumber::Second);
        assert_eq!(result, None);

        let digest = hasher.finalize();
        let digest_prime = Md5Collider::new().hash_blocks(&m0_prime, &m1_prime);
        assert_eq!(digest, digest_prime)
    }
    
    #[test]
    fn test_collision_2() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";
        const M1_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";
        const M0_PRIME_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b";
        const M1_PRIME_HEX : &str = "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";

        let m0 = decode_hex_block(M0_HEX);
        let m0_prime_test = decode_hex_block(M0_PRIME_HEX);
        let mut m0_prime = m0.clone();

        modify_word_le(&mut m0_prime, 4, 1 << 31, true);
        modify_word_le(&mut m0_prime, 11, 1 << 15, true);
        modify_word_le(&mut m0_prime, 14, 1 << 31, true);
        assert_eq!(m0_prime, m0_prime_test);
        
        let m1 = decode_hex_block(M1_HEX);
        let m1_prime_test = decode_hex_block(M1_PRIME_HEX);
        let mut m1_prime = m1.clone();

        modify_word_le(&mut m1_prime, 4, 1 << 31, true);
        modify_word_le(&mut m1_prime, 11, 1 << 15, false);
        modify_word_le(&mut m1_prime, 14, 1 << 31, true);
        assert_eq!(m1_prime, m1_prime_test);

        let mut hasher = Md5Collider::new();
        hasher.compress_block(&m0);
        let result = hasher.verify_full(&m1, BlockNumber::Second);
        assert_eq!(result, None);

        let digest = hasher.finalize();
        let digest_prime = Md5Collider::new().hash_blocks(&m0_prime, &m1_prime);
        assert_eq!(digest, digest_prime)
    }

    #[test]
    fn test_generation() {
        const M0_HEX : &str = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b";

        let mut rng = rand::rng();

        let m0 = decode_hex_block(M0_HEX);
        let mut hasher = Md5Collider::new();
        hasher.compress_block(&m0);
        let state = hasher.get_state();

        for _ in 1..100 {
            let m1 = gen_message(state, BlockNumber::Second, GenType::SMM, &mut rng);
            let result = hasher.verify_full(&m1, BlockNumber::Second);
            
            if let Some(k) = result {
                assert!(k >= 16);
            }
        }

    }
}
